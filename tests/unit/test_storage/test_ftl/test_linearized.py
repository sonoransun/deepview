"""Tests for ``LinearizedFlashLayer``."""
from __future__ import annotations

import io
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.ftl.badblock import BadBlockRemapTranslator
from deepview.storage.ftl.linearized import LinearizedFlashLayer
from deepview.storage.geometry import NANDGeometry

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class MemoryDataLayer(DataLayer):
    """In-memory BytesIO-backed DataLayer (data-only; no OOB)."""

    def __init__(self, data: bytes, name: str = "mem") -> None:
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


PAGE_SIZE = 512
SPARE_SIZE = 16
PAGES_PER_BLOCK = 1
BLOCKS = 8


def _geometry() -> NANDGeometry:
    return NANDGeometry(
        page_size=PAGE_SIZE,
        spare_size=SPARE_SIZE,
        pages_per_block=PAGES_PER_BLOCK,
        blocks=BLOCKS,
    )


def _incrementing(total: int) -> bytes:
    return bytes(i & 0xFF for i in range(total))


class TestLinearizedFlashLayer:
    def test_read_returns_full_backing(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo)
        assert layer.read(0, BLOCKS * PAGE_SIZE) == raw

    def test_partial_read_across_pages(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo)
        # Read spanning 3 logical pages starting mid-page.
        start = PAGE_SIZE - 10
        length = PAGE_SIZE * 2 + 20
        assert layer.read(start, length) == raw[start : start + length]

    def test_maximum_address_matches_translator(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo)
        assert layer.maximum_address == BLOCKS * PAGE_SIZE - 1
        assert layer.minimum_address == 0

    def test_metadata_default_name(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo)
        assert layer.metadata.name == "linearized:badblock"

    def test_metadata_custom_name(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo, name="custom")
        assert layer.metadata.name == "custom"

    def test_is_valid_bounds(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo)
        assert layer.is_valid(0, BLOCKS * PAGE_SIZE)
        assert not layer.is_valid(0, BLOCKS * PAGE_SIZE + 1)
        assert not layer.is_valid(-1, 1)

    def test_write_raises(self) -> None:
        raw = _incrementing(BLOCKS * PAGE_SIZE)
        backing = MemoryDataLayer(raw)
        geo = _geometry()
        trans = BadBlockRemapTranslator(geo, bad_blocks=set())
        layer = LinearizedFlashLayer(backing, trans, geo)
        try:
            layer.write(0, b"x")
        except NotImplementedError:
            return
        raise AssertionError("write() should have raised NotImplementedError")
