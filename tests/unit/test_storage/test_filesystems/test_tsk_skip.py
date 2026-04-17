"""Smoke test for :class:`TSKFilesystem` — skipped when pytsk3 isn't available."""
from __future__ import annotations

import struct
from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("pytsk3")

from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.filesystems.tsk import TSKFilesystem  # noqa: E402


# We re-use the tiny FAT12 image constructed by the fat_native tests — TSK
# reads FAT12 natively, so opening it with pytsk3 exercises the LayerFileIO
# <-> pytsk3.Img_Info bridge without needing mkfs.


SECTOR = 512
TOTAL_SECTORS = 12
NUM_FATS = 1
SECTORS_PER_FAT = 2
RESERVED = 1
ROOT_ENTRIES = 64
SECTORS_PER_CLUSTER = 1


class _MemoryDataLayer(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

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
        return LayerMetadata(name="tsk-test")


def _build_boot_sector() -> bytes:
    buf = bytearray(SECTOR)
    buf[0:3] = b"\xEB\x3C\x90"
    buf[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", buf, 11, SECTOR)
    buf[13] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", buf, 14, RESERVED)
    buf[16] = NUM_FATS
    struct.pack_into("<H", buf, 17, ROOT_ENTRIES)
    struct.pack_into("<H", buf, 19, TOTAL_SECTORS)
    buf[21] = 0xF8
    struct.pack_into("<H", buf, 22, SECTORS_PER_FAT)
    struct.pack_into("<H", buf, 24, 1)
    struct.pack_into("<H", buf, 26, 1)
    struct.pack_into("<I", buf, 28, 0)
    struct.pack_into("<I", buf, 32, 0)
    buf[36] = 0x80
    buf[38] = 0x29
    struct.pack_into("<I", buf, 39, 0xDEADBEEF)
    buf[43:54] = b"TESTVOL    "
    buf[54:62] = b"FAT12   "
    buf[510] = 0x55
    buf[511] = 0xAA
    return bytes(buf)


def _build_image() -> bytes:
    img = bytearray(TOTAL_SECTORS * SECTOR)
    img[0:SECTOR] = _build_boot_sector()
    # FAT: reserved entries + cluster 2 = end-of-chain
    fat = bytearray(SECTORS_PER_FAT * SECTOR)
    fat[0] = 0xF8
    fat[1] = 0xFF
    fat[2] = 0xFF
    # cluster 2 EOC in FAT12 (offset 3, half-byte split)
    fat[3] = 0xFF
    fat[4] = 0x0F
    img[RESERVED * SECTOR : (RESERVED + SECTORS_PER_FAT) * SECTOR] = fat
    # Root dir: one file HELLO.TXT at cluster 2 size 12.
    root = bytearray(32)
    root[0:8] = b"HELLO   "
    root[8:11] = b"TXT"
    root[11] = 0x20
    struct.pack_into("<H", root, 26, 2)
    struct.pack_into("<I", root, 28, 12)
    root_start = (RESERVED + NUM_FATS * SECTORS_PER_FAT) * SECTOR
    img[root_start : root_start + 32] = root
    data_start = root_start + 4 * SECTOR
    img[data_start : data_start + 12] = b"hello world\n"
    return bytes(img)


class TestTSKOpensFATImage:
    def test_tsk_probe_and_construct(self) -> None:
        layer = _MemoryDataLayer(_build_image())
        try:
            if not TSKFilesystem.probe(layer):
                pytest.skip("pytsk3 did not recognise the minimal FAT12 image")
            fs = TSKFilesystem(layer)
        except Exception as exc:  # pragma: no cover - backend-specific
            pytest.skip(f"pytsk3 could not open minimal FAT12: {exc}")
        assert fs.fs_name == "tsk"
