"""Windows 10/11 standby-list compressed memory store DataLayer.

Starting with Windows 10 1511, the memory manager compresses idle standby-
list pages into a per-process compressed store (``MMPAGING_FILE`` backed,
colloquially known as the "Memory Compression" process). Each page in the
store is typically Xpress-compressed; some builds also support a raw
passthrough for pages that did not compress below a size threshold.

This layer pairs a backing :class:`DataLayer` holding the raw store blob
with a page-map describing each compressed page's location, length, and
algorithm tag, and exposes the virtual decompressed address space as a
flat DataLayer.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import TYPE_CHECKING, Literal

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.encodings.xpress import decompress_xpress

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

__all__ = ["StandbyCompressionLayer", "StandbyPageAlgo"]

StandbyPageAlgo = Literal["xpress", "raw"]


class StandbyCompressionLayer(DataLayer):
    """Windows compressed memory store flattened into a DataLayer.

    Parameters
    ----------
    backing:
        Backing :class:`DataLayer` containing the raw compressed store bytes.
    page_map:
        List of ``(virtual_pfn, offset_in_store, compressed_length, algo)``
        tuples. ``virtual_pfn`` is the logical page frame number inside the
        decompressed address space; ``algo`` is ``"xpress"`` or ``"raw"``.
    page_size:
        Logical page size (default 4096).
    name:
        Optional layer name for metadata.
    """

    def __init__(
        self,
        backing: DataLayer,
        page_map: list[tuple[int, int, int, StandbyPageAlgo]],
        page_size: int = 4096,
        name: str = "",
    ) -> None:
        self._backing = backing
        self._page_size = page_size
        self._name = name or "windows_standby_compression"
        # Index by virtual_pfn -> (offset, clen, algo).
        self._entries: dict[int, tuple[int, int, StandbyPageAlgo]] = {}
        for vpfn, offset_in_store, clen, algo in page_map:
            if algo not in ("xpress", "raw"):
                raise ValueError(f"StandbyCompressionLayer: unknown algo {algo!r}")
            self._entries[vpfn] = (offset_in_store, clen, algo)
        if self._entries:
            self._min_pfn = min(self._entries)
            self._max_pfn = max(self._entries)
        else:
            self._min_pfn = 0
            self._max_pfn = 0
        self._decompress_page_cached = lru_cache(maxsize=256)(self._decompress_page)

    # ------------------------------------------------------------------
    # Decompression
    # ------------------------------------------------------------------

    def _decompress_page(self, virtual_pfn: int) -> bytes:
        entry = self._entries.get(virtual_pfn)
        if entry is None:
            return b"\x00" * self._page_size
        offset_in_store, clen, algo = entry
        if clen == 0:
            return b"\x00" * self._page_size
        blob = self._backing.read(offset_in_store, clen)
        if len(blob) < clen:
            return b"\x00" * self._page_size
        if algo == "raw":
            out = blob
        elif algo == "xpress":
            out = decompress_xpress(blob, self._page_size)
        else:  # pragma: no cover - exhaustive Literal
            raise ValueError(f"Unsupported standby algo: {algo!r}")
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
        raise NotImplementedError("StandbyCompressionLayer is read-only")

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
    def minimum_address(self) -> int:
        return self._min_pfn * self._page_size

    @property
    def maximum_address(self) -> int:
        if not self._entries:
            return 0
        return (self._max_pfn + 1) * self._page_size - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            os="windows",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )
