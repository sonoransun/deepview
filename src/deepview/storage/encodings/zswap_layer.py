"""Linux zswap (compressed frontswap pool) DataLayer.

``zswap`` is a Linux kernel feature that interposes on the swap path and
keeps recently-swapped pages compressed in RAM instead of writing them to
the backing swap device. Unlike zram it is *not* a block device: the only
way to recover data is to extract the zpool (``zbud`` or ``zsmalloc``) from
a kernel-memory dump and hand the resulting per-page blob list to this
layer.

The layer's shape mirrors :class:`ZRAMLayer`; the only differences are the
``zpool`` tag (carried in metadata for operator diagnostics) and the fact
that a zswap page may have been evicted to the real swap device, in which
case it simply won't appear in *page_table*.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import TYPE_CHECKING, Literal

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

__all__ = ["ZswapLayer"]

ZswapAlgo = Literal["lzo", "lz4", "zstd", "deflate"]
ZswapZPool = Literal["zbud", "zsmalloc"]


class ZswapLayer(DataLayer):
    """DataLayer view over a zswap zpool page-blob list."""

    def __init__(
        self,
        backing: DataLayer,
        page_table: list[tuple[int, int, int]],
        zpool: ZswapZPool = "zsmalloc",
        algo: ZswapAlgo = "lzo",
        page_size: int = 4096,
        name: str = "",
    ) -> None:
        self._backing = backing
        self._zpool: ZswapZPool = zpool
        self._algo: ZswapAlgo = algo
        self._page_size = page_size
        self._name = name or f"zswap:{zpool}:{algo}"
        self._entries: dict[int, tuple[int, int]] = {}
        for logical_idx, backing_offset, clen in page_table:
            self._entries[logical_idx] = (backing_offset, clen)
        if self._entries:
            self._min_page = min(self._entries)
            self._max_page = max(self._entries)
        else:
            self._min_page = 0
            self._max_page = 0
        self._decompress_page_cached = lru_cache(maxsize=256)(self._decompress_page)

    # ------------------------------------------------------------------
    # Decompression
    # ------------------------------------------------------------------

    def _decompress_page(self, page_index: int) -> bytes:
        entry = self._entries.get(page_index)
        if entry is None:
            return b"\x00" * self._page_size
        backing_offset, clen = entry
        if clen == 0:
            return b"\x00" * self._page_size
        blob = self._backing.read(backing_offset, clen)
        if len(blob) < clen:
            return b"\x00" * self._page_size

        if self._algo == "lz4":
            import lz4.block  # type: ignore[import-not-found]

            out = lz4.block.decompress(blob, uncompressed_size=self._page_size)
        elif self._algo == "zstd":
            import zstandard  # type: ignore[import-not-found]

            dctx = zstandard.ZstdDecompressor()
            out = dctx.decompress(blob, max_output_size=self._page_size)
        elif self._algo == "lzo":
            import lzo  # type: ignore[import-not-found]

            out = lzo.decompress(blob, False, self._page_size)
        elif self._algo == "deflate":
            import zlib

            out = zlib.decompress(blob, bufsize=self._page_size)
        else:  # pragma: no cover - exhaustive Literal
            raise ValueError(f"Unsupported zswap algo: {self._algo!r}")

        if len(out) < self._page_size:
            out = out + b"\x00" * (self._page_size - len(out))
        elif len(out) > self._page_size:
            out = out[: self._page_size]
        return out

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        result = bytearray()
        remaining = length
        cur = offset
        end_addr = self.maximum_address
        while remaining > 0:
            if cur < 0 or cur > end_addr:
                if pad:
                    result.extend(b"\x00" * remaining)
                    return bytes(result)
                break
            page_index = cur // self._page_size
            page_offset = cur % self._page_size
            available = self._page_size - page_offset
            chunk = min(remaining, available)
            page = self._decompress_page_cached(page_index)
            result.extend(page[page_offset:page_offset + chunk])
            cur += chunk
            remaining -= chunk
        if pad and len(result) < length:
            result.extend(b"\x00" * (length - len(result)))
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("ZswapLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        return offset + length <= self.maximum_address + 1

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        yield from scanner.scan_layer(self, progress_callback=progress_callback)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def zpool(self) -> ZswapZPool:
        return self._zpool

    @property
    def algo(self) -> ZswapAlgo:
        return self._algo

    @property
    def minimum_address(self) -> int:
        return self._min_page * self._page_size

    @property
    def maximum_address(self) -> int:
        if not self._entries:
            return 0
        return (self._max_page + 1) * self._page_size - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            os="linux",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )
