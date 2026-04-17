"""Linux zram compressed-swap DataLayer.

``zram`` is a block-device kernel facility that stores every logical page
compressed in RAM (typically with lzo-rle, lz4, or zstd). This layer wraps a
backing :class:`DataLayer` — the raw decoded zram backing store, as produced
by ``/sys/block/zram*/reset`` + `mem_used_total` snapshotting — together with
a page table mapping logical page indices to their compressed on-disk slice,
and lazily decompresses pages on read.

The optional libraries ``lz4``, ``zstandard``, ``lzo`` are imported inside
the ``_decompress_page`` branch so importing this module at runtime with a
bare-core install never fails.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import TYPE_CHECKING, Literal

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

__all__ = ["ZRAMLayer"]

ZRAMAlgo = Literal["lzo", "lz4", "zstd"]


class ZRAMLayer(DataLayer):
    """DataLayer view over a zram compressed page table.

    Parameters
    ----------
    backing:
        The :class:`DataLayer` holding the compressed page blobs.
    algo:
        Compression algorithm identifier — ``"lzo"``, ``"lz4"``, or
        ``"zstd"``. Matched against the zram device's
        ``/sys/block/zram*/comp_algorithm`` setting.
    page_table:
        A list of ``(logical_page_index, backing_offset, compressed_length)``
        tuples. The logical indices need not be contiguous; missing pages
        are treated as zero-filled.
    page_size:
        Logical page size in bytes (default 4096).
    name:
        Optional layer name for metadata.
    """

    def __init__(
        self,
        backing: DataLayer,
        algo: ZRAMAlgo,
        page_table: list[tuple[int, int, int]],
        page_size: int = 4096,
        name: str = "",
    ) -> None:
        self._backing = backing
        self._algo: ZRAMAlgo = algo
        self._page_size = page_size
        self._name = name or f"zram:{algo}"
        # Index page-table entries by logical page index for O(1) lookup.
        self._entries: dict[int, tuple[int, int]] = {}
        for logical_idx, backing_offset, clen in page_table:
            self._entries[logical_idx] = (backing_offset, clen)
        if self._entries:
            self._min_page = min(self._entries)
            self._max_page = max(self._entries)
        else:
            self._min_page = 0
            self._max_page = 0
        # Wrap the bound method via lru_cache; ``maxsize=256`` keeps a few
        # megabytes of decompressed pages hot.
        self._decompress_page_cached = lru_cache(maxsize=256)(self._decompress_page)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _decompress_page(self, page_index: int) -> bytes:
        """Decompress a single logical page (cache-visible)."""
        entry = self._entries.get(page_index)
        if entry is None:
            return b"\x00" * self._page_size
        backing_offset, clen = entry
        if clen == 0:
            # A zero-length compressed entry represents an all-zero page.
            return b"\x00" * self._page_size
        blob = self._backing.read(backing_offset, clen)
        if len(blob) < clen:
            # Backing is truncated; surface a zero page rather than crashing.
            return b"\x00" * self._page_size

        if self._algo == "lz4":
            import lz4.frame  # type: ignore[import-not-found]

            try:
                out = lz4.frame.decompress(blob)
            except Exception:
                # zram's ``lz4`` is actually the raw block format on older
                # kernels; fall back to the block decoder.
                import lz4.block  # type: ignore[import-not-found]

                out = lz4.block.decompress(blob, uncompressed_size=self._page_size)
        elif self._algo == "zstd":
            import zstandard  # type: ignore[import-not-found]

            dctx = zstandard.ZstdDecompressor()
            out = dctx.decompress(blob, max_output_size=self._page_size)
        elif self._algo == "lzo":
            import lzo  # type: ignore[import-not-found]

            out = lzo.decompress(blob, False, self._page_size)
        else:  # pragma: no cover - exhaustive Literal
            raise ValueError(f"Unsupported zram algo: {self._algo!r}")

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
        raise NotImplementedError("ZRAMLayer is read-only")

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
    # DataLayer properties
    # ------------------------------------------------------------------

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
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )
