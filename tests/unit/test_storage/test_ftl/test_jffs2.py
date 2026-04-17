"""Tests for ``JFFS2Translator``."""
from __future__ import annotations

import io
import struct
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.ftl.jffs2 import JFFS2Translator
from deepview.storage.geometry import NANDGeometry

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

PAGE_SIZE = 512
SPARE_SIZE = 0
PAGES_PER_BLOCK = 4
BLOCKS = 2


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


def _build_node(totlen: int) -> bytes:
    """Build a node with magic ``0x1985`` and ``totlen`` little-endian."""
    hdr = bytearray(totlen)
    hdr[0:2] = b"\x85\x19"
    struct.pack_into("<H", hdr, 2, 0xE001)  # nodetype (arbitrary)
    struct.pack_into("<I", hdr, 4, totlen)
    return bytes(hdr)


def _build_chip(offsets: list[int], node_len: int = 64) -> bytes:
    total = BLOCKS * PAGES_PER_BLOCK * PAGE_SIZE
    raw = bytearray(b"\xFF" * total)
    for off in offsets:
        node = _build_node(node_len)
        raw[off : off + node_len] = node
    return bytes(raw)


class TestJFFS2Translator:
    def test_probe_detects_magic(self) -> None:
        raw = _build_chip([0])
        layer = _BytesLayer(raw)
        assert JFFS2Translator.probe(layer, _geometry()) is True

    def test_probe_false_without_magic(self) -> None:
        layer = _BytesLayer(b"\xFF" * (BLOCKS * PAGES_PER_BLOCK * PAGE_SIZE))
        assert JFFS2Translator.probe(layer, _geometry()) is False

    def test_build_map_yields_two_nodes(self) -> None:
        raw = _build_chip([0, 128])
        layer = _BytesLayer(raw)
        trans = JFFS2Translator(_geometry())
        mappings = list(trans.build_map(layer, _geometry()))
        assert len(mappings) == 2
        assert mappings[0].physical.data_offset == 0
        assert mappings[1].physical.data_offset == 128

    def test_build_map_assigns_sequential_lbas(self) -> None:
        raw = _build_chip([0, 256])
        layer = _BytesLayer(raw)
        trans = JFFS2Translator(_geometry())
        mappings = list(trans.build_map(layer, _geometry()))
        assert [m.lba for m in mappings] == [0, 1]
