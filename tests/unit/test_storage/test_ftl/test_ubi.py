"""Tests for ``UBITranslator``."""
from __future__ import annotations

import io
import struct
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.ftl.ubi import UBITranslator
from deepview.storage.geometry import NANDGeometry

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

PAGE_SIZE = 2048
SPARE_SIZE = 64
PAGES_PER_BLOCK = 64
BLOCKS = 4
TOTAL_PAGE_SIZE = PAGE_SIZE + SPARE_SIZE
BLOCK_SIZE = PAGES_PER_BLOCK * TOTAL_PAGE_SIZE


class _BytesLayer(DataLayer):
    """Minimal BytesIO-backed DataLayer for tests."""

    def __init__(self, data: bytes, name: str = "bytes") -> None:
        self._buf = io.BytesIO(data)
        self._size = len(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        self._buf.seek(offset)
        raw = self._buf.read(length)
        if pad and len(raw) < length:
            raw = raw + b"\x00" * (length - len(raw))
        return raw

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= self._size

    def scan(
        self,
        scanner: "PatternScanner",
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return self._size - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name, minimum_address=0, maximum_address=self._size)


def _geometry() -> NANDGeometry:
    return NANDGeometry(
        page_size=PAGE_SIZE,
        spare_size=SPARE_SIZE,
        pages_per_block=PAGES_PER_BLOCK,
        blocks=BLOCKS,
    )


def _build_ec_header(vid_hdr_offset: int = 2048, data_offset: int = 4096) -> bytes:
    """64-byte UBI EC header with the minimum fields our parser cares about."""
    hdr = bytearray(64)
    hdr[0:4] = b"UBI#"
    struct.pack_into(">I", hdr, 16, vid_hdr_offset)
    struct.pack_into(">I", hdr, 20, data_offset)
    return bytes(hdr)


def _build_vid_header(vol_id: int, lnum: int) -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"UBI!"
    struct.pack_into(">I", hdr, 8, vol_id)
    struct.pack_into(">I", hdr, 12, lnum)
    return bytes(hdr)


def _build_chip(lnums: list[int]) -> bytes:
    """Build a chip image where each block has the EC + VID headers installed."""
    assert len(lnums) == BLOCKS
    raw = bytearray(BLOCKS * BLOCK_SIZE)
    for block_idx, lnum in enumerate(lnums):
        base = block_idx * BLOCK_SIZE
        ec = _build_ec_header(vid_hdr_offset=2048, data_offset=4096)
        raw[base : base + len(ec)] = ec
        vid = _build_vid_header(vol_id=0, lnum=lnum)
        raw[base + 2048 : base + 2048 + len(vid)] = vid
    return bytes(raw)


class TestUBITranslator:
    def test_probe_detects_ubi_magic(self) -> None:
        layer = _BytesLayer(_build_chip([0, 1, 2, 3]))
        assert UBITranslator.probe(layer, _geometry()) is True

    def test_probe_false_without_magic(self) -> None:
        layer = _BytesLayer(b"\xFF" * (BLOCKS * BLOCK_SIZE))
        assert UBITranslator.probe(layer, _geometry()) is False

    def test_build_map_yields_one_per_block(self) -> None:
        layer = _BytesLayer(_build_chip([0, 1, 2, 3]))
        trans = UBITranslator(_geometry())
        mappings = list(trans.build_map(layer, _geometry()))
        assert len(mappings) == BLOCKS

    def test_build_map_lnum_drives_lba(self) -> None:
        # Install LEBs in reverse order so LBAs don't equal block indices.
        layer = _BytesLayer(_build_chip([3, 2, 1, 0]))
        trans = UBITranslator(_geometry())
        mappings = list(trans.build_map(layer, _geometry()))
        lnums = [m.lba for m in mappings]
        assert lnums == [3, 2, 1, 0]
        # Translating LBA 0 should give the mapping for block 3.
        m0 = trans.translate(0)
        assert m0 is not None
        assert m0.physical.block == 3
