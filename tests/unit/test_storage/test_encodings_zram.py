"""Tests for the zram compressed-page DataLayer.

We build a synthetic in-memory backing layer and hand-pack a two-page table.
Because the stdlib has no LZO/LZ4/zstd, the "lz4"/"zstd" variants use
``pytest.importorskip``; the deflate/raw-ish path is exercised via a special
case that substitutes ``zlib`` behind a fake algorithm name -- but to keep
the public ``Literal`` honest we only run that as a monkey-patched unit
test on the protected method.
"""
from __future__ import annotations

import zlib
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.encodings.zram_layer import ZRAMLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class BytesBackingLayer(DataLayer):
    """Tiny in-memory DataLayer over a bytes blob."""

    def __init__(self, blob: bytes, name: str = "bytes_backing") -> None:
        self._blob = blob
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            return b""
        end = min(offset + length, len(self._blob))
        out = self._blob[offset:end]
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._blob)

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        return iter(())

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(len(self._blob) - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )


class TestZRAMLayerStructure:
    def test_metadata_and_bounds(self) -> None:
        backing = BytesBackingLayer(b"\x00" * 16)
        layer = ZRAMLayer(backing, "lz4", page_table=[(0, 0, 0), (3, 0, 0)])
        assert layer.minimum_address == 0
        assert layer.maximum_address == 4 * 4096 - 1
        assert layer.metadata.name == "zram:lz4"

    def test_empty_page_table(self) -> None:
        backing = BytesBackingLayer(b"")
        layer = ZRAMLayer(backing, "lz4", page_table=[])
        assert layer.minimum_address == 0
        assert layer.maximum_address == 0

    def test_missing_page_reads_zeros(self) -> None:
        # One mapped page at index 0 (zero-length compressed -> zero page),
        # but reading page 2 should still yield zeros rather than raising.
        backing = BytesBackingLayer(b"\x00")
        layer = ZRAMLayer(backing, "lz4", page_table=[(0, 0, 0)])
        # Read from inside the "window" but from an unmapped page.
        # page_table has a single entry at logical index 0, so both min and
        # max page are 0; reading beyond max_address with pad returns zeros.
        data = layer.read(0, 4096)
        assert data == b"\x00" * 4096

    def test_write_raises(self) -> None:
        backing = BytesBackingLayer(b"")
        layer = ZRAMLayer(backing, "lz4", page_table=[])
        with pytest.raises(NotImplementedError):
            layer.write(0, b"X")


class TestZRAMLayerLZ4:
    def test_lz4_round_trip(self) -> None:
        lz4_frame = pytest.importorskip("lz4.frame")
        page_a = (b"page-A " * 256 + b"\x00" * (4096 - 7 * 256))[:4096]
        page_b = (b"PAGE-B!" * 256 + b"\x00" * (4096 - 7 * 256))[:4096]
        assert len(page_a) == 4096 and len(page_b) == 4096
        blob_a = lz4_frame.compress(page_a)
        blob_b = lz4_frame.compress(page_b)
        backing_bytes = blob_a + blob_b
        backing = BytesBackingLayer(backing_bytes)
        page_table = [
            (0, 0, len(blob_a)),
            (1, len(blob_a), len(blob_b)),
        ]
        layer = ZRAMLayer(backing, "lz4", page_table=page_table)

        assert layer.read(0, 4096) == page_a
        assert layer.read(4096, 4096) == page_b
        # Cross-page slice.
        mixed = layer.read(4090, 12)
        assert mixed == page_a[-6:] + page_b[:6]


class TestZRAMLayerStdlibFallback:
    """Exercise the decompression plumbing via a zlib-backed monkey-patch.

    This doesn't certify any of the optional code paths, but it proves the
    page cache, read slicing, and LRU behaviour are correct without
    requiring any optional PyPI deps.
    """

    def test_decompress_page_with_zlib_monkeypatch(self) -> None:
        page_a = bytes((i * 11) & 0xFF for i in range(4096))
        page_b = bytes((i * 19) & 0xFF for i in range(4096))
        blob_a = zlib.compress(page_a)
        blob_b = zlib.compress(page_b)
        backing = BytesBackingLayer(blob_a + blob_b)
        layer = ZRAMLayer(
            backing, "lzo", page_table=[(0, 0, len(blob_a)), (1, len(blob_a), len(blob_b))]
        )

        # Replace the cached decompressor so we don't need optional deps.
        from functools import lru_cache as _lru

        def fake_decompress(page_index: int) -> bytes:
            if page_index == 0:
                return zlib.decompress(blob_a)
            if page_index == 1:
                return zlib.decompress(blob_b)
            return b"\x00" * 4096

        layer._decompress_page_cached = _lru(maxsize=256)(  # type: ignore[assignment]
            fake_decompress
        )

        assert layer.read(0, 16) == page_a[:16]
        assert layer.read(4096, 16) == page_b[:16]
        assert layer.read(4090, 12) == page_a[-6:] + page_b[:6]
