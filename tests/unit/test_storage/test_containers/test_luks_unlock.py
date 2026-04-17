"""End-to-end LUKS1 unlock + decrypt roundtrip test.

Skips when any of the required slices aren't available:
- ``cryptography`` (header cipher primitives)
- ``deepview.storage.containers.layer`` (DecryptedVolumeLayer)
- ``deepview.offload.engine`` (offload pipeline)
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct
from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("deepview.storage.containers.layer")
pytest.importorskip("deepview.offload.engine")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from deepview.core.context import AnalysisContext  # noqa: E402
from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.containers._af_split import af_split  # noqa: E402
from deepview.storage.containers.luks import LUKSUnlocker  # noqa: E402
from deepview.storage.containers.unlock import Passphrase  # noqa: E402

_KEY_BYTES = 32  # AES-256 master key half
_MK_LEN = 64  # XTS key = two halves concatenated
_STRIPES = 10  # tiny stripe count so the test stays fast
_KM_OFFSET_SECTORS = 2
_PAYLOAD_OFFSET_SECTORS = _KM_OFFSET_SECTORS + 4  # a couple of sectors for keyslot data
_PASSPHRASE = "test1234"
_HASH = "sha256"
_KEYSLOT_ITER = 1000
_MK_ITER = 500


def _pad(s: bytes, n: int) -> bytes:
    return s + b"\x00" * (n - len(s))


def _aes_xts_encrypt(key: bytes, sector: int, block: bytes) -> bytes:
    tweak = sector.to_bytes(16, "little")
    c = Cipher(algorithms.AES(key), modes.XTS(tweak))
    return c.encryptor().update(block)


def _encrypt_keyslot_stripes(keyslot_key: bytes, stripes: bytes) -> bytes:
    """Encrypt the stripes buffer with AES-XTS under *keyslot_key*.

    Sector numbers start at 0 and increment for each 512-byte chunk.
    """
    out = bytearray()
    sector_size = 512
    sectors = (len(stripes) + sector_size - 1) // sector_size
    for s in range(sectors):
        start = s * sector_size
        end = min(start + sector_size, len(stripes))
        block = stripes[start:end]
        if len(block) < sector_size:
            block = block + b"\x00" * (sector_size - len(block))
        ct = _aes_xts_encrypt(keyslot_key, s, block)
        out.extend(ct[: end - start])
    # Keep a multiple of sector_size for decryption symmetry.
    remainder = len(out) % sector_size
    if remainder:
        out.extend(b"\x00" * (sector_size - remainder))
    return bytes(out)


def _build_luks1_image(master_key: bytes, passphrase: str, plaintext: bytes) -> bytes:
    """Build a minimal-but-valid LUKS1 image backed by AES-XTS."""
    assert len(master_key) == _MK_LEN
    # Digest LUKS1 fields.
    mk_digest_salt = os.urandom(32)
    mk_digest = hashlib.pbkdf2_hmac(
        _HASH, master_key, mk_digest_salt, _MK_ITER, 20
    )
    keyslot_salt = os.urandom(32)
    # Derive keyslot-decryption key via PBKDF2 of the passphrase.
    keyslot_key = hashlib.pbkdf2_hmac(
        _HASH, passphrase.encode("utf-8"), keyslot_salt, _KEYSLOT_ITER, _MK_LEN
    )
    # AF-split the master key into stripes.
    random_bytes = os.urandom(_MK_LEN * (_STRIPES - 1))
    split_stripes = af_split(master_key, _STRIPES, random_bytes, hash_name=_HASH)
    assert len(split_stripes) == _MK_LEN * _STRIPES
    encrypted_stripes = _encrypt_keyslot_stripes(keyslot_key, split_stripes)

    # Build the header.
    buf = bytearray(592)
    buf[0:6] = b"LUKS\xba\xbe"
    buf[6:8] = struct.pack(">H", 1)
    buf[8:40] = _pad(b"aes", 32)
    buf[40:72] = _pad(b"xts-plain64", 32)
    buf[72:104] = _pad(_HASH.encode("utf-8"), 32)
    buf[104:108] = struct.pack(">I", _PAYLOAD_OFFSET_SECTORS)
    buf[108:112] = struct.pack(">I", _MK_LEN)
    buf[112:132] = mk_digest
    buf[132:164] = mk_digest_salt
    buf[164:168] = struct.pack(">I", _MK_ITER)
    buf[168:208] = _pad(b"11111111-2222-3333-4444-555555555555", 40)
    # Keyslot 0 — active.
    ks_off = 208
    buf[ks_off : ks_off + 4] = struct.pack(">I", 0x00AC71F3)
    buf[ks_off + 4 : ks_off + 8] = struct.pack(">I", _KEYSLOT_ITER)
    buf[ks_off + 8 : ks_off + 40] = keyslot_salt
    buf[ks_off + 40 : ks_off + 44] = struct.pack(">I", _KM_OFFSET_SECTORS)
    buf[ks_off + 44 : ks_off + 48] = struct.pack(">I", _STRIPES)
    # Keyslots 1..7 — inactive.
    for i in range(1, 8):
        off = 208 + i * 48
        buf[off : off + 4] = struct.pack(">I", 0x0000DEAD)

    # Assemble the full image:
    # [header pad to km_offset][encrypted stripes pad to payload][payload ciphertext]
    image = bytearray()
    image.extend(buf)
    km_offset_bytes = _KM_OFFSET_SECTORS * 512
    image.extend(b"\x00" * (km_offset_bytes - len(image)))
    image.extend(encrypted_stripes)
    # Pad to payload offset.
    payload_offset_bytes = _PAYLOAD_OFFSET_SECTORS * 512
    if len(image) < payload_offset_bytes:
        image.extend(b"\x00" * (payload_offset_bytes - len(image)))
    # Encrypt the plaintext with the master key (AES-XTS, sector 0..).
    assert len(plaintext) % 512 == 0
    for s in range(len(plaintext) // 512):
        ct = _aes_xts_encrypt(master_key, s, plaintext[s * 512 : (s + 1) * 512])
        image.extend(ct)
    return bytes(image)


class _Mem(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = self._data[offset:end]
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
        return LayerMetadata(name="luks_img")


def test_luks1_unlock_roundtrip_with_passphrase() -> None:
    """Full LUKS1 stack: passphrase -> PBKDF2 -> decrypt stripes -> AF-merge
    -> verify mk_digest -> DecryptedVolumeLayer -> read plaintext."""
    plaintext = bytes(((i * 37 + 11) & 0xFF) for i in range(512))  # one sector
    master_key = bytes(range(_MK_LEN))  # deterministic
    image = _build_luks1_image(master_key, _PASSPHRASE, plaintext)
    layer = _Mem(image)

    unlocker = LUKSUnlocker()
    # Force the unlocker to use the test AnalysisContext's offload engine.
    ctx = AnalysisContext.for_testing()
    unlocker._offload_engine = ctx.offload  # type: ignore[attr-defined]

    header = unlocker.detect(layer)
    assert header is not None
    assert header.format == "luks1"
    assert header.data_offset == _PAYLOAD_OFFSET_SECTORS * 512

    # Run unlock.
    source = Passphrase(passphrase=_PASSPHRASE)
    decrypted = asyncio.run(unlocker.unlock(layer, header, source))

    # Read the first sector and compare.
    out = decrypted.read(0, 512)
    assert out == plaintext


def test_luks1_unlock_wrong_passphrase_fails() -> None:
    plaintext = bytes(((i * 37 + 11) & 0xFF) for i in range(512))
    master_key = bytes(range(_MK_LEN))
    image = _build_luks1_image(master_key, _PASSPHRASE, plaintext)
    layer = _Mem(image)

    unlocker = LUKSUnlocker()
    ctx = AnalysisContext.for_testing()
    unlocker._offload_engine = ctx.offload  # type: ignore[attr-defined]
    header = unlocker.detect(layer)
    assert header is not None

    with pytest.raises(RuntimeError, match="verification failed"):
        asyncio.run(unlocker.unlock(layer, header, Passphrase(passphrase="wrong")))
