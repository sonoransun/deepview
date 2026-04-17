"""Tests for the pure-Python FAT12 reader."""
from __future__ import annotations

import struct
from collections.abc import Callable, Iterator

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.filesystems.fat_native import FATFilesystem


class _MemoryDataLayer(DataLayer):
    """Minimal in-memory :class:`DataLayer` used by these tests."""

    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._data = bytes(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0:
            return b"\x00" * length if pad else b""
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
        return LayerMetadata(name=self._name)


# --------------------------------------------------------------------------
# Hand-crafted FAT12 image
#
# Layout (12 sectors of 512 bytes = 6144 bytes):
#   sector 0       boot sector
#   sectors 1-2    FAT (2 sectors)
#   sectors 3-6    root directory (4 sectors -> 64 entries)
#   sectors 7-11   data region (5 sectors, 1 cluster each)
#
# sectors_per_cluster = 1 -> cluster 2 = sector 7, cluster 3 = sector 8, ...
# --------------------------------------------------------------------------


SECTOR = 512
TOTAL_SECTORS = 12
NUM_FATS = 1
SECTORS_PER_FAT = 2
RESERVED = 1
ROOT_ENTRIES = 64  # 64 * 32 = 2048 = 4 sectors
SECTORS_PER_CLUSTER = 1


def _build_boot_sector() -> bytes:
    buf = bytearray(SECTOR)
    # jmp boot + nop
    buf[0:3] = b"\xEB\x3C\x90"
    buf[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", buf, 11, SECTOR)  # bytes per sector
    buf[13] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", buf, 14, RESERVED)
    buf[16] = NUM_FATS
    struct.pack_into("<H", buf, 17, ROOT_ENTRIES)
    struct.pack_into("<H", buf, 19, TOTAL_SECTORS)  # total sectors (16-bit)
    buf[21] = 0xF8  # media type
    struct.pack_into("<H", buf, 22, SECTORS_PER_FAT)
    struct.pack_into("<H", buf, 24, 1)  # sectors per track
    struct.pack_into("<H", buf, 26, 1)  # heads
    struct.pack_into("<I", buf, 28, 0)  # hidden
    struct.pack_into("<I", buf, 32, 0)  # total sectors (32-bit)
    buf[36] = 0x80  # drive number
    buf[38] = 0x29  # boot signature
    struct.pack_into("<I", buf, 39, 0xDEADBEEF)  # volume ID
    buf[43:54] = b"TESTVOL    "
    buf[54:62] = b"FAT12   "
    buf[510] = 0x55
    buf[511] = 0xAA
    return bytes(buf)


def _build_fat12(entries: dict[int, int]) -> bytes:
    """Build a FAT12 table of SECTORS_PER_FAT * SECTOR bytes.

    *entries* maps cluster index -> next-cluster value (12-bit).
    """
    fat = bytearray(SECTORS_PER_FAT * SECTOR)
    # Reserved entries: 0 = media type, 1 = 0xFFF.
    entries.setdefault(0, 0xFF8)
    entries.setdefault(1, 0xFFF)
    for cluster, value in entries.items():
        off = (cluster * 3) // 2
        if cluster & 1:
            # high nibble of off, all of off+1
            lo = fat[off] & 0x0F
            fat[off] = lo | ((value & 0x0F) << 4)
            fat[off + 1] = (value >> 4) & 0xFF
        else:
            fat[off] = value & 0xFF
            hi = fat[off + 1] & 0xF0
            fat[off + 1] = hi | ((value >> 8) & 0x0F)
    return bytes(fat)


def _build_dir_entry(
    name_8: str,
    ext_3: str,
    *,
    attr: int,
    start_cluster: int,
    size: int,
) -> bytes:
    buf = bytearray(32)
    name = name_8.ljust(8)[:8].encode("ascii").upper()
    ext = ext_3.ljust(3)[:3].encode("ascii").upper()
    buf[0:8] = name
    buf[8:11] = ext
    buf[11] = attr
    # Time/date fields left zero.
    struct.pack_into("<H", buf, 26, start_cluster & 0xFFFF)
    struct.pack_into("<H", buf, 20, (start_cluster >> 16) & 0xFFFF)
    struct.pack_into("<I", buf, 28, size)
    return bytes(buf)


def _build_image() -> bytes:
    payload = b"hello world\n"
    assert len(payload) <= SECTOR  # fits in one cluster

    img = bytearray(TOTAL_SECTORS * SECTOR)
    # Sector 0: boot
    img[0:SECTOR] = _build_boot_sector()
    # Sectors 1-2: FAT — cluster 2 is end-of-chain.
    fat_bytes = _build_fat12({2: 0xFFF})
    img[RESERVED * SECTOR : (RESERVED + SECTORS_PER_FAT) * SECTOR] = fat_bytes
    # Sectors 3-6: root dir — one entry pointing at cluster 2, size 12.
    root_start = (RESERVED + NUM_FATS * SECTORS_PER_FAT) * SECTOR
    entry = _build_dir_entry("HELLO", "TXT", attr=0x20, start_cluster=2, size=len(payload))
    img[root_start : root_start + 32] = entry
    # Sector 7 (cluster 2): file contents.
    data_start = root_start + 4 * SECTOR
    img[data_start : data_start + len(payload)] = payload
    return bytes(img)


@pytest.fixture
def fat_image() -> bytes:
    return _build_image()


class TestFATNative:
    def test_probe_matches(self, fat_image: bytes) -> None:
        layer = _MemoryDataLayer(fat_image)
        assert FATFilesystem.probe(layer) is True

    def test_list_root_returns_hello_txt(self, fat_image: bytes) -> None:
        layer = _MemoryDataLayer(fat_image)
        fs = FATFilesystem(layer)
        entries = list(fs.list("/"))
        assert len(entries) == 1
        entry = entries[0]
        assert entry.path == "/HELLO.TXT"
        assert entry.size == len(b"hello world\n")
        assert entry.is_dir is False
        assert entry.is_deleted is False
        assert entry.extra["fs"] == "fat"
        assert entry.extra["start_cluster"] == 2

    def test_read_file_contents(self, fat_image: bytes) -> None:
        layer = _MemoryDataLayer(fat_image)
        fs = FATFilesystem(layer)
        assert fs.read("/HELLO.TXT") == b"hello world\n"

    def test_open_returns_layer_with_file_bytes(self, fat_image: bytes) -> None:
        layer = _MemoryDataLayer(fat_image)
        fs = FATFilesystem(layer)
        file_layer = fs.open("/HELLO.TXT")
        assert file_layer.read(0, 5) == b"hello"
        assert file_layer.read(6, 5) == b"world"
        assert file_layer.maximum_address == 11

    def test_stat_matches_list(self, fat_image: bytes) -> None:
        layer = _MemoryDataLayer(fat_image)
        fs = FATFilesystem(layer)
        entry = fs.stat("/HELLO.TXT")
        assert entry.size == 12
        assert entry.is_dir is False

    def test_deleted_entry_surfaced_when_requested(self, fat_image: bytes) -> None:
        # Flip the first byte of the root directory entry to 0xE5 — the
        # canonical FAT "deleted file" marker.
        buf = bytearray(fat_image)
        root_start = (RESERVED + NUM_FATS * SECTORS_PER_FAT) * SECTOR
        buf[root_start] = 0xE5
        layer = _MemoryDataLayer(bytes(buf))
        fs = FATFilesystem(layer)
        # Default: deleted entry is hidden.
        assert len(list(fs.list("/"))) == 0
        deleted = list(fs.list("/", include_deleted=True))
        assert len(deleted) == 1
        assert deleted[0].is_deleted is True
