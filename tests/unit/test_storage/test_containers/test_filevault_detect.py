"""FileVault 2 detection test with a synthesized Core Storage header."""
from __future__ import annotations

from collections.abc import Callable, Iterator

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.containers.filevault2 import FileVault2Unlocker


class _MemLayer(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = self._data[max(0, offset):end]
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
        return LayerMetadata(name="mem")


def _synth_core_storage_header() -> bytes:
    """Build a 4 KiB image with the ``CS`` Core Storage marker at 0x10."""
    buf = bytearray(b"\x00" * 4096)
    # 8-byte checksum placeholder at 0x00..0x07.
    buf[0x00:0x08] = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    # Core Storage signature at 0x10.
    buf[0x10:0x12] = b"CS"
    return bytes(buf)


def _synth_apfs_header() -> bytes:
    """Build a 4 KiB image with the ``NXSB`` APFS superblock at 0x20."""
    buf = bytearray(b"\x00" * 4096)
    buf[0x20:0x24] = b"NXSB"
    return bytes(buf)


def test_filevault_detect_core_storage() -> None:
    layer = _MemLayer(_synth_core_storage_header())
    header = FileVault2Unlocker().detect(layer)
    assert header is not None
    assert header.format == "filevault2"
    assert header.sector_size == 512
    assert header.cipher.startswith("aes")
    assert header.data_offset == 0
    assert header.data_length > 0
    assert header.kdf == "pbkdf2_sha256"
    assert b"CS" in header.raw[0x10:0x12]


def test_filevault_detect_apfs() -> None:
    layer = _MemLayer(_synth_apfs_header())
    header = FileVault2Unlocker().detect(layer)
    assert header is not None
    assert header.format == "filevault2"


def test_filevault_detect_negative_random() -> None:
    layer = _MemLayer(b"\xAA" * 4096)
    assert FileVault2Unlocker().detect(layer) is None


def test_filevault_detect_negative_too_short() -> None:
    layer = _MemLayer(b"\x00" * 4)
    assert FileVault2Unlocker().detect(layer) is None
