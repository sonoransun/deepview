"""Hidden-volume VeraCrypt unlock test.

Builds an outer volume whose standard header encrypts one passphrase
and whose *hidden* header — positioned at ``total_size - 65_536`` — is
encrypted with a *different* passphrase. Verifies:

* ``try_hidden=False`` unlocks only the standard volume with the outer
  passphrase; the inner passphrase fails.
* ``try_hidden=True`` unlocks the inner volume with the inner
  passphrase even though the outer passphrase was never supplied.
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

_HEADER_SIZE = 65_536
_SALT_LEN = 64
_ENC_HDR_LEN = 448
_SECTOR = 512
# Outer payload must be large enough to fit the hidden volume header at
# its tail (modern layout: hidden_header_offset = total_size - 65_536).
_OUTER_PAYLOAD_SECTORS = 256  # 128 KiB — comfortably > one header worth
_OUTER_PAYLOAD_LEN = _SECTOR * _OUTER_PAYLOAD_SECTORS
_HIDDEN_PAYLOAD_SECTORS = 8
_HIDDEN_PAYLOAD_LEN = _SECTOR * _HIDDEN_PAYLOAD_SECTORS
_ITERATIONS = 1000

_OUTER_PASSPHRASE = "OuterPass"
_INNER_PASSPHRASE = "InnerPass"


class _MemoryLayer(DataLayer):
    def __init__(self, data: bytes | bytearray) -> None:
        self._data = bytearray(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = bytes(self._data[offset:end])
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self, scanner: object, progress_callback: Callable | None = None
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


def _xts(key64: bytes, sector: int, block: bytes, *, encrypt: bool) -> bytes:
    tweak = sector.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key64), modes.XTS(tweak))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(block)


def _build_decrypted_header(
    *,
    master: bytes,
    tweak: bytes,
    encrypted_area_start: int,
    encrypted_area_size: int,
    volume_size: int,
    hidden_volume_size: int,
) -> bytes:
    buf = bytearray(_ENC_HDR_LEN)
    buf[0:4] = b"VERA"
    struct.pack_into(">H", buf, 4, 5)
    struct.pack_into(">H", buf, 6, 0x10B)
    # crc_keys filled after key area
    struct.pack_into(">Q", buf, 28, hidden_volume_size)
    struct.pack_into(">Q", buf, 36, volume_size)
    struct.pack_into(">Q", buf, 44, encrypted_area_start)
    struct.pack_into(">Q", buf, 52, encrypted_area_size)
    struct.pack_into(">I", buf, 60, 0)
    struct.pack_into(">I", buf, 64, _SECTOR)
    key_area = bytearray(256)
    key_area[0:32] = master
    key_area[32:64] = tweak
    buf[192:192 + 256] = key_area
    struct.pack_into(">I", buf, 8, zlib.crc32(bytes(key_area)) & 0xFFFFFFFF)
    data_crc = zlib.crc32(bytes(buf[0:188])) & 0xFFFFFFFF
    struct.pack_into(">I", buf, 188, data_crc)
    return bytes(buf)


def _header_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512", passphrase.encode("utf-8"), salt, _ITERATIONS, 64
    )


def _encrypt_sectors(key64: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    sectors = len(plaintext) // _SECTOR
    for s in range(sectors):
        out.extend(
            _xts(key64, s, plaintext[s * _SECTOR:(s + 1) * _SECTOR], encrypt=True)
        )
    return bytes(out)


def _build_hidden_fixture() -> tuple[bytes, bytes, bytes]:
    """Build an image with one outer + one hidden volume.

    Returns ``(image, outer_plaintext, hidden_plaintext)``.
    """
    total = _HEADER_SIZE + _OUTER_PAYLOAD_LEN
    image = bytearray(total)

    # --- Outer volume ---
    outer_salt = bytes(range(_SALT_LEN))
    outer_master = bytes((i * 5 + 2) & 0xFF for i in range(32))
    outer_tweak = bytes((i * 9 + 17) & 0xFF for i in range(32))
    outer_key64 = outer_master + outer_tweak
    outer_header_plain = _build_decrypted_header(
        master=outer_master,
        tweak=outer_tweak,
        encrypted_area_start=_HEADER_SIZE,
        encrypted_area_size=_OUTER_PAYLOAD_LEN,
        volume_size=total,
        hidden_volume_size=_HIDDEN_PAYLOAD_LEN,
    )
    outer_header_ct = _xts(
        _header_key(_OUTER_PASSPHRASE, outer_salt), 0, outer_header_plain,
        encrypt=True,
    )
    outer_plain = bytearray()
    for s in range(_OUTER_PAYLOAD_SECTORS):
        outer_plain.extend(bytes(((s * 33 + i) & 0xFF) for i in range(_SECTOR)))
    outer_ct = _encrypt_sectors(outer_key64, bytes(outer_plain))

    image[0:_SALT_LEN] = outer_salt
    image[_SALT_LEN:_SALT_LEN + _ENC_HDR_LEN] = outer_header_ct
    image[_HEADER_SIZE:_HEADER_SIZE + _OUTER_PAYLOAD_LEN] = outer_ct

    # --- Hidden volume (modern layout: header at total - 65_536) ---
    hidden_header_offset = total - _HEADER_SIZE
    hidden_salt = bytes((i ^ 0xAA) for i in range(_SALT_LEN))
    hidden_master = bytes((i * 3 + 41) & 0xFF for i in range(32))
    hidden_tweak = bytes((i * 19 + 53) & 0xFF for i in range(32))
    hidden_key64 = hidden_master + hidden_tweak
    # Place the hidden encrypted area just after the outer header but
    # before the tail region where the hidden header itself lives. In a
    # real VeraCrypt volume the operator picks this offset; any location
    # inside the outer payload that does not overlap the hidden header
    # works for the test.
    hidden_enc_start = _HEADER_SIZE  # immediately after the outer header
    hidden_header_plain = _build_decrypted_header(
        master=hidden_master,
        tweak=hidden_tweak,
        encrypted_area_start=hidden_enc_start,
        encrypted_area_size=_HIDDEN_PAYLOAD_LEN,
        volume_size=total,
        hidden_volume_size=_HIDDEN_PAYLOAD_LEN,
    )
    hidden_header_ct = _xts(
        _header_key(_INNER_PASSPHRASE, hidden_salt),
        0,
        hidden_header_plain,
        encrypt=True,
    )
    hidden_plain = bytearray()
    for s in range(_HIDDEN_PAYLOAD_SECTORS):
        hidden_plain.extend(bytes(((s * 77 + i) & 0xFF) for i in range(_SECTOR)))
    hidden_ct = _encrypt_sectors(hidden_key64, bytes(hidden_plain))

    image[hidden_header_offset:hidden_header_offset + _SALT_LEN] = hidden_salt
    image[
        hidden_header_offset + _SALT_LEN:hidden_header_offset + _SALT_LEN + _ENC_HDR_LEN
    ] = hidden_header_ct
    # Overwrite the trailing payload region with the hidden ciphertext.
    image[hidden_enc_start:hidden_enc_start + _HIDDEN_PAYLOAD_LEN] = hidden_ct

    return bytes(image), bytes(outer_plain), bytes(hidden_plain)


def test_outer_passphrase_unlocks_standard_only() -> None:
    image, outer_plain, _ = _build_hidden_fixture()
    layer = _MemoryLayer(image)
    unlocker = VeraCryptUnlocker(override_iterations=_ITERATIONS)
    header = unlocker.detect(layer)
    assert header is not None

    # Without try_hidden we get the outer volume.
    unlocked = asyncio.run(
        unlocker.unlock(
            layer, header, Passphrase(passphrase=_OUTER_PASSPHRASE),
            try_hidden=False,
        )
    )
    # Read from BEYOND the hidden payload window (which overwrote the
    # first HIDDEN_PAYLOAD_LEN bytes of the outer payload with hidden
    # ciphertext). Hidden payload is at sectors [0..8); sector 16 is
    # safely outer-only.
    start = _HIDDEN_PAYLOAD_LEN + _SECTOR  # one sector past the hidden window
    assert unlocked.read(start, _SECTOR) == outer_plain[start:start + _SECTOR]


def test_hidden_passphrase_requires_try_hidden() -> None:
    image, _, hidden_plain = _build_hidden_fixture()
    layer = _MemoryLayer(image)
    unlocker = VeraCryptUnlocker(override_iterations=_ITERATIONS)
    header = unlocker.detect(layer)
    assert header is not None

    # The inner passphrase does not unlock the outer header.
    with pytest.raises(RuntimeError):
        asyncio.run(
            unlocker.unlock(
                layer,
                header,
                Passphrase(passphrase=_INNER_PASSPHRASE),
                try_hidden=False,
            )
        )

    # With try_hidden=True it finds the hidden header at total-65_536.
    unlocked = asyncio.run(
        unlocker.unlock(
            layer,
            header,
            Passphrase(passphrase=_INNER_PASSPHRASE),
            try_hidden=True,
        )
    )
    # Only the first hidden sector needs to match; the layer wraps the
    # hidden encrypted_area_start+size defined in the hidden header.
    assert unlocked.read(0, _SECTOR) == hidden_plain[:_SECTOR]
    assert unlocked.read(0, _HIDDEN_PAYLOAD_LEN) == hidden_plain
