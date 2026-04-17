"""End-to-end VeraCrypt AES-XTS unlock + roundtrip test.

Builds a synthetic, self-consistent VeraCrypt volume in memory:

* 64 bytes of salt
* 448 bytes of hand-crafted plaintext header encrypted with AES-XTS using
  a PBKDF2-HMAC-SHA512 derivation of the passphrase (with ``override_iterations``
  kept at 1000 to keep the test under a second)
* the rest of the 65 536-byte header region zero-padded
* 16 sectors of payload encrypted with the header's master/tweak keys

Then asserts:

* ``VeraCryptUnlocker.detect`` returns a header with ``kdf="trial-decrypt"``.
* ``VeraCryptUnlocker.unlock`` with the correct passphrase produces a
  :class:`DecryptedVolumeLayer` that decrypts every payload sector to
  the original plaintext.
* Unlock with a wrong passphrase raises.

Skipped when any of ``cryptography``, the layer module, or the offload
engine is not importable — keeps the core install CI green.
"""
from __future__ import annotations

import asyncio
import hashlib
import struct
import zlib
from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("deepview.storage.containers.layer")
pytest.importorskip("deepview.offload.engine")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.containers.unlock import Passphrase  # noqa: E402
from deepview.storage.containers.veracrypt import VeraCryptUnlocker  # noqa: E402

# ---------------------------------------------------------------------------
# Test-scale constants
# ---------------------------------------------------------------------------

_HEADER_SIZE = 65_536
_SALT_LEN = 64
_ENC_HDR_LEN = 448
_SECTOR = 512
_PAYLOAD_SECTORS = 16
_PAYLOAD_LEN = _SECTOR * _PAYLOAD_SECTORS
_ITERATIONS = 1000  # test-only — matches VeraCryptUnlocker.override_iterations
_PASSPHRASE = "TestPass"


class _MemoryLayer(DataLayer):
    """In-memory DataLayer with write support for fixture construction."""

    def __init__(self, data: bytes | bytearray) -> None:
        self._data = bytearray(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = bytes(self._data[offset:end])
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        end = offset + len(data)
        if end > len(self._data):
            self._data.extend(b"\x00" * (end - len(self._data)))
        self._data[offset:end] = data

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self,
        scanner: object,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._data) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name="fixture")


def _xts_encrypt(key64: bytes, sector: int, block: bytes) -> bytes:
    tweak = sector.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key64), modes.XTS(tweak))
    return cipher.encryptor().update(block)


def _xts_decrypt(key64: bytes, sector: int, block: bytes) -> bytes:
    tweak = sector.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key64), modes.XTS(tweak))
    return cipher.decryptor().update(block)


def _build_decrypted_header(master_key: bytes, tweak_key: bytes) -> bytes:
    """Lay out the 448-byte VeraCrypt header plaintext.

    Matches the offsets `_parse_header` expects.
    """
    buf = bytearray(_ENC_HDR_LEN)
    # magic
    buf[0:4] = b"VERA"
    # version (5)
    struct.pack_into(">H", buf, 4, 5)
    # required_version
    struct.pack_into(">H", buf, 6, 0x10B)
    # crc_keys at offset 8 — fill in after we know the key area
    # reserved[16] at 12
    # hidden_vol_size at 28
    struct.pack_into(">Q", buf, 28, 0)
    # volume_size at 36 (total outer = _HEADER_SIZE + payload)
    total_vol = _HEADER_SIZE + _PAYLOAD_LEN
    struct.pack_into(">Q", buf, 36, total_vol)
    # encrypted_area_start at 44 — right after the header
    struct.pack_into(">Q", buf, 44, _HEADER_SIZE)
    # encrypted_area_size at 52
    struct.pack_into(">Q", buf, 52, _PAYLOAD_LEN)
    # flag_bits at 60
    struct.pack_into(">I", buf, 60, 0)
    # sector_size at 64
    struct.pack_into(">I", buf, 64, _SECTOR)
    # reserved[120] at 68..=187 (already zeroed)
    # master-key area at 192..=447
    key_area = bytearray(256)
    key_area[0:32] = master_key
    key_area[32:64] = tweak_key
    buf[192:192 + 256] = key_area
    # crc_keys at 8 (CRC of the 256-byte key area), big-endian
    struct.pack_into(">I", buf, 8, zlib.crc32(bytes(key_area)) & 0xFFFFFFFF)
    # crc_data at 252 — CRC over bytes [0..188)
    data_crc = zlib.crc32(bytes(buf[0:188])) & 0xFFFFFFFF
    struct.pack_into(">I", buf, 188, data_crc)
    return bytes(buf)


def _build_fixture() -> tuple[bytes, bytes]:
    """Build the encrypted volume image + expected plaintext payload.

    Returns ``(image_bytes, expected_plaintext_payload)``.
    """
    salt = bytes(range(_SALT_LEN))
    # Derive the header key with the same iteration count the unlocker
    # will use in ``override_iterations`` mode.
    header_key = hashlib.pbkdf2_hmac(
        "sha512",
        _PASSPHRASE.encode("utf-8"),
        salt,
        _ITERATIONS,
        64,
    )

    # Pick a deterministic master + tweak for the payload.
    master = bytes((i * 7 + 13) & 0xFF for i in range(32))
    tweak = bytes((i * 11 + 29) & 0xFF for i in range(32))
    payload_key64 = master + tweak

    # Plaintext header (the 448 bytes that get encrypted with the
    # *header* key).
    header_plain = _build_decrypted_header(master, tweak)
    header_ct = _xts_encrypt(header_key, 0, header_plain)

    # Payload: each sector is an easy-to-verify pattern so failures are
    # easy to read in diff output.
    payload_plain = bytearray()
    for s in range(_PAYLOAD_SECTORS):
        block = bytes(((s * 256 + i) & 0xFF) for i in range(_SECTOR))
        payload_plain.extend(block)
    # Encrypt each sector with sector-number-keyed tweak. VeraCrypt
    # numbers the payload starting at sector 0 relative to
    # encrypted_area_start.
    payload_ct = bytearray()
    for s in range(_PAYLOAD_SECTORS):
        start = s * _SECTOR
        payload_ct.extend(
            _xts_encrypt(payload_key64, s, bytes(payload_plain[start:start + _SECTOR]))
        )

    # Assemble the on-disk image.
    image = bytearray(_HEADER_SIZE + _PAYLOAD_LEN)
    image[0:_SALT_LEN] = salt
    image[_SALT_LEN:_SALT_LEN + _ENC_HDR_LEN] = header_ct
    image[_HEADER_SIZE:_HEADER_SIZE + _PAYLOAD_LEN] = bytes(payload_ct)
    return bytes(image), bytes(payload_plain)


def test_veracrypt_aes_xts_unlock_reads_payload() -> None:
    image, expected = _build_fixture()
    layer = _MemoryLayer(image)

    unlocker = VeraCryptUnlocker(override_iterations=_ITERATIONS)
    header = unlocker.detect(layer)
    assert header is not None, "detect must succeed for a candidate VeraCrypt volume"
    assert header.format == "veracrypt"
    assert header.kdf == "trial-decrypt"

    source = Passphrase(passphrase=_PASSPHRASE)
    unlocked = asyncio.run(unlocker.unlock(layer, header, source))
    assert unlocked is not None
    assert unlocked.metadata.name == "veracrypt:aes-xts"
    assert unlocked.maximum_address + 1 == _PAYLOAD_LEN

    # Read back the whole payload and verify every byte matches.
    plaintext = unlocked.read(0, _PAYLOAD_LEN)
    assert plaintext == expected

    # A targeted sector-1 read must also agree.
    assert unlocked.read(_SECTOR, _SECTOR) == expected[_SECTOR:2 * _SECTOR]


def test_veracrypt_wrong_passphrase_fails() -> None:
    image, _ = _build_fixture()
    layer = _MemoryLayer(image)

    unlocker = VeraCryptUnlocker(override_iterations=_ITERATIONS)
    header = unlocker.detect(layer)
    assert header is not None

    bad = Passphrase(passphrase="not-the-right-pass")
    with pytest.raises(RuntimeError):
        asyncio.run(unlocker.unlock(layer, header, bad))


def test_veracrypt_master_key_path() -> None:
    """When a MasterKey is supplied, unlock must bypass the KDF entirely."""
    image, expected = _build_fixture()
    layer = _MemoryLayer(image)

    # Re-derive the header key the same way the fixture did.
    salt = bytes(range(_SALT_LEN))
    header_key = hashlib.pbkdf2_hmac(
        "sha512", _PASSPHRASE.encode("utf-8"), salt, _ITERATIONS, 64
    )

    from deepview.storage.containers.unlock import MasterKey

    unlocker = VeraCryptUnlocker(override_iterations=_ITERATIONS)
    header = unlocker.detect(layer)
    assert header is not None

    unlocked = asyncio.run(
        unlocker.unlock(layer, header, MasterKey(key=header_key))
    )
    assert unlocked.read(0, _SECTOR) == expected[:_SECTOR]
