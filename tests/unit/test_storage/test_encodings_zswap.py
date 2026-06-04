"""Tests for the zswap compressed-page DataLayer.

Mirrors the zram tests: a synthetic in-memory backing layer + a hand-packed
page table. Accelerated codecs (lz4/lzo/zstd) are skip-gated; deflate uses
stdlib zlib and always runs.
"""
from __future__ import annotations

import zlib
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.encodings.zswap_layer import ZswapLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class BytesBackingLayer(DataLayer):
    def __init__(self, blob: bytes, name: str = "bytes_backing") -> None:
        self._blob = blob
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            return b""
        out = self._blob[offset : min(offset + length, len(self._blob))]
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._blob)

    def scan(
        self, scanner: PatternScanner, progress_callback: Callable | None = None
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


def _page(tag: bytes) -> bytes:
    page = (tag * (4096 // len(tag) + 1))[:4096]
    assert len(page) == 4096
    return page


class TestZswapDeflate:
    def test_deflate_round_trip_stdlib(self) -> None:
        page = _page(b"deflate-")
        blob = zlib.compress(page)
        backing = BytesBackingLayer(blob)
        layer = ZswapLayer(backing, [(0, 0, len(blob))], algo="deflate")
        assert layer.read(0, 4096) == page
        assert layer.metadata.name == "zswap:zsmalloc:deflate"


class TestZswapAcceleratedCodecs:
    def test_lz4_block_round_trip(self) -> None:
        lz4_block = pytest.importorskip("lz4.block")
        page = _page(b"lz4blk-")
        blob = lz4_block.compress(page, store_size=False)
        backing = BytesBackingLayer(blob)
        layer = ZswapLayer(backing, [(0, 0, len(blob))], algo="lz4")
        assert layer.read(0, 4096) == page

    def test_zstd_round_trip(self) -> None:
        zstd = pytest.importorskip("zstandard")
        page = _page(b"zstd-")
        blob = zstd.ZstdCompressor().compress(page)
        backing = BytesBackingLayer(blob)
        layer = ZswapLayer(backing, [(0, 0, len(blob))], algo="zstd")
        assert layer.read(0, 4096) == page

    def test_lzo_round_trip(self) -> None:
        lzo = pytest.importorskip("lzo")
        page = _page(b"lzo-")
        blob = lzo.compress(page, 1, False)
        backing = BytesBackingLayer(blob)
        layer = ZswapLayer(backing, [(0, 0, len(blob))], algo="lzo")
        assert layer.read(0, 4096) == page


class TestZswapMissingCodec:
    def test_missing_codec_raises_clear_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "lzo":
                raise ImportError("forced for test")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", fake_import)
        backing = BytesBackingLayer(b"\xff\xff\xff\xff")
        layer = ZswapLayer(backing, [(0, 0, 4)], algo="lzo")
        with pytest.raises(ImportError, match=r"deepview\[compression\]"):
            layer.read(0, 4096)
