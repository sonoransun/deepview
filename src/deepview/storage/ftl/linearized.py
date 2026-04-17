"""Linearized flash data layer.

Presents a backing data-only layer (typically an ``ECCDataLayer``) as a
flat byte-addressable logical surface by walking an :class:`FTLTranslator`
for each logical byte range. A tiny 4-entry ring cache keeps the most
recently decoded logical pages hot to smooth the common sequential-read
case.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.ftl import FTLTranslator
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry
from deepview.storage.manager import StorageError

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class LinearizedFlashLayer(DataLayer):
    """Expose an FTL-translated flash surface as a flat logical ``DataLayer``."""

    _CACHE_SIZE = 4

    def __init__(
        self,
        backing: DataLayer,
        translator: FTLTranslator,
        geometry: NANDGeometry,
        name: str = "",
    ) -> None:
        self._backing = backing
        self._translator = translator
        self._geometry = geometry
        self._name = name or f"linearized:{translator.name}"
        self._page_cache: OrderedDict[int, bytes] = OrderedDict()

    # ------------------------------------------------------------------
    # DataLayer protocol
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length <= 0:
            return b""
        page_size = self._geometry.page_size
        out = bytearray()
        remaining = length
        cursor = offset
        max_addr = self._translator.logical_size()
        while remaining > 0:
            if max_addr and cursor >= max_addr:
                if pad:
                    out.extend(b"\x00" * remaining)
                break
            lba = cursor // page_size
            intra = cursor % page_size
            mapping = self._translator.translate(lba)
            if mapping is None:
                if pad:
                    chunk_len = min(page_size - intra, remaining)
                    out.extend(b"\x00" * chunk_len)
                    cursor += chunk_len
                    remaining -= chunk_len
                    continue
                raise StorageError(f"unmapped LBA {lba}")
            page_bytes = self._read_page(mapping.physical.data_offset)
            available = page_size - intra
            take = min(available, remaining)
            out.extend(page_bytes[intra : intra + take])
            cursor += take
            remaining -= take
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("Linearized flash layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        max_addr = self._translator.logical_size()
        if max_addr == 0:
            return False
        return offset + length <= max_addr

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        max_addr = self._translator.logical_size()
        if max_addr == 0:
            return
        chunk_size = max(self._geometry.page_size * 16, 65536)
        offset = 0
        while offset < max_addr:
            end = min(offset + chunk_size, max_addr)
            chunk = self.read(offset, end - offset, pad=True)
            yield from scanner.scan(chunk, offset=offset)
            if progress_callback:
                progress_callback(end / max_addr)
            offset = end

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        size = self._translator.logical_size()
        return (size - 1) if size > 0 else 0

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _read_page(self, raw_data_offset: int) -> bytes:
        """Read a single logical page from the backing (data-only) layer.

        The translator returns offsets in raw-NAND coordinates (including
        spare). The backing layer is data-only, so we rescale by
        ``page_size / total_page_size``.
        """
        geo = self._geometry
        total = geo.total_page_size
        if total <= 0:
            raise StorageError("invalid NAND geometry: total_page_size <= 0")
        backing_offset = (raw_data_offset // total) * geo.page_size
        cached = self._page_cache.get(backing_offset)
        if cached is not None:
            self._page_cache.move_to_end(backing_offset)
            return cached
        page = self._backing.read(backing_offset, geo.page_size, pad=True)
        if len(page) < geo.page_size:
            page = page + b"\x00" * (geo.page_size - len(page))
        self._page_cache[backing_offset] = page
        if len(self._page_cache) > self._CACHE_SIZE:
            self._page_cache.popitem(last=False)
        return page
