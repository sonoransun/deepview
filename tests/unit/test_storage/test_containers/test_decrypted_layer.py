"""Tests for :class:`DecryptedVolumeLayer` over AES-XTS ciphertext."""
from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.containers.layer import DecryptedVolumeLayer  # noqa: E402


class MemoryDataLayer(DataLayer):
    """Trivial in-memory :class:`DataLayer` shim for tests."""

    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._data = bytes(data)
        self._name = name

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
        return LayerMetadata(name=self._name)


SECTOR = 512
KEY = bytes(range(64))  # 64-byte key -> AES-256-XTS


def _encrypt_sectors(plaintext: bytes) -> bytes:
    out = bytearray()
    sectors = len(plaintext) // SECTOR
    for i in range(sectors):
        tweak = i.to_bytes(16, "little")
        enc = Cipher(algorithms.AES(KEY), modes.XTS(tweak)).encryptor()
        out.extend(enc.update(plaintext[i * SECTOR:(i + 1) * SECTOR]))
    return bytes(out)


def test_read_spans_multiple_sectors() -> None:
    plaintext = bytes(((i * 7 + 3) & 0xFF) for i in range(4 * SECTOR))
    ciphertext = _encrypt_sectors(plaintext)

    underlying = MemoryDataLayer(ciphertext)
    layer = DecryptedVolumeLayer(
        underlying,
        cipher_name="aes",
        key=KEY,
        sector_size=SECTOR,
        mode="xts",
        iv_mode="tweak",
    )

    # Read all 4 sectors (2048 bytes) in one call.
    assert layer.read(0, 4 * SECTOR) == plaintext
    # Bounds / metadata.
    assert layer.minimum_address == 0
    assert layer.maximum_address == 4 * SECTOR - 1
    assert layer.is_valid(0, 4 * SECTOR)
    assert not layer.is_valid(0, 4 * SECTOR + 1)


def test_per_sector_iv_math_is_correct() -> None:
    """Reading sector 1 alone must produce the same plaintext as the
    corresponding slice of a full multi-sector read — proving the
    per-sector tweak is computed from the sector number, not the byte
    offset into the encrypted volume."""
    plaintext = bytes(((i * 13 + 5) & 0xFF) for i in range(4 * SECTOR))
    ciphertext = _encrypt_sectors(plaintext)
    underlying = MemoryDataLayer(ciphertext)

    layer = DecryptedVolumeLayer(
        underlying,
        cipher_name="aes",
        key=KEY,
        sector_size=SECTOR,
        mode="xts",
        iv_mode="tweak",
    )

    s1 = layer.read(SECTOR, SECTOR)
    assert s1 == plaintext[SECTOR:2 * SECTOR]

    # Also verify an unaligned read across a sector boundary.
    window = layer.read(SECTOR - 8, 32)
    assert window == plaintext[SECTOR - 8:SECTOR + 24]


def test_sector_cache_roundtrips_identical_output() -> None:
    """Re-reading the same sector must return identical bytes (cache hit)."""
    plaintext = bytes((i & 0xFF) for i in range(2 * SECTOR))
    ciphertext = _encrypt_sectors(plaintext)
    underlying = MemoryDataLayer(ciphertext)
    layer = DecryptedVolumeLayer(
        underlying,
        cipher_name="aes",
        key=KEY,
        sector_size=SECTOR,
        mode="xts",
    )
    first = layer.read(0, SECTOR)
    second = layer.read(0, SECTOR)
    assert first == second == plaintext[:SECTOR]


def test_write_is_not_implemented() -> None:
    underlying = MemoryDataLayer(b"\x00" * SECTOR)
    layer = DecryptedVolumeLayer(
        underlying, cipher_name="aes", key=KEY, sector_size=SECTOR
    )
    with pytest.raises(NotImplementedError):
        layer.write(0, b"x")
