"""Tests for StandbyCompressionLayer."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.encodings.standby_compression import StandbyCompressionLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class BytesBackingLayer(DataLayer):
    def __init__(self, blob: bytes) -> None:
        self._blob = blob

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
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
        return LayerMetadata(name="standby_backing")


def _literals_block(payload: bytes) -> bytes:
    """Build an all-literal Xpress block (matches the encoder in the xpress test)."""
    out = bytearray()
    i = 0
    n = len(payload)
    while i < n:
        out.extend(b"\x00\x00\x00\x00")
        take = min(32, n - i)
        out.extend(payload[i:i + take])
        i += take
    return bytes(out)


class TestStandbyCompressionLayer:
    def test_raw_page_passthrough(self) -> None:
        page = bytes((i * 3 + 1) & 0xFF for i in range(4096))
        backing = BytesBackingLayer(page)
        layer = StandbyCompressionLayer(
            backing,
            page_map=[(0, 0, 4096, "raw")],
        )
        assert layer.read(0, 4096) == page

    def test_xpress_page_decompresses(self) -> None:
        # Build a 4KiB page, encode it as all-literal Xpress, and wrap it.
        page = (b"ABCDEFGH" * 512)[:4096]
        compressed = _literals_block(page)
        backing = BytesBackingLayer(compressed)
        layer = StandbyCompressionLayer(
            backing,
            page_map=[(0, 0, len(compressed), "xpress")],
        )
        got = layer.read(0, 4096)
        assert got == page

    def test_multiple_pages_and_sparse_pfn(self) -> None:
        page_a = (b"\x11" * 4096)
        page_b = (b"\x22" * 4096)
        blob_a = _literals_block(page_a)
        blob_b = _literals_block(page_b)
        backing = BytesBackingLayer(blob_a + blob_b)
        layer = StandbyCompressionLayer(
            backing,
            page_map=[
                (0, 0, len(blob_a), "xpress"),
                (3, len(blob_a), len(blob_b), "xpress"),
            ],
        )
        assert layer.read(0, 16) == b"\x11" * 16
        # Unmapped PFN 1 and 2 -> zeros.
        assert layer.read(4096, 16) == b"\x00" * 16
        assert layer.read(2 * 4096, 16) == b"\x00" * 16
        # PFN 3 decodes to page_b.
        assert layer.read(3 * 4096, 16) == b"\x22" * 16
        assert layer.maximum_address == 4 * 4096 - 1

    def test_unknown_algo_rejected(self) -> None:
        backing = BytesBackingLayer(b"")
        with pytest.raises(ValueError, match="unknown algo"):
            StandbyCompressionLayer(
                backing,
                page_map=[(0, 0, 0, "lz4")],  # type: ignore[list-item]
            )

    def test_write_raises(self) -> None:
        backing = BytesBackingLayer(b"")
        layer = StandbyCompressionLayer(backing, page_map=[])
        with pytest.raises(NotImplementedError):
            layer.write(0, b"X")
