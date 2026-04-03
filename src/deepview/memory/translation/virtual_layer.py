"""Virtual address DataLayer backed by page table translation."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.exceptions import TranslationError
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.memory.translation.page_tables import (
    PAGE_4K,
    PageTableWalker,
    VirtualMapping,
)

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class VirtualAddressLayer(DataLayer):
    """DataLayer that translates virtual addresses via page table walking.

    Wraps a physical ``DataLayer`` and a CR3 value, transparently converting
    all :meth:`read` calls from virtual to physical addresses.  Handles reads
    that span page boundaries by splitting them across translated pages.
    """

    def __init__(
        self,
        physical_layer: DataLayer,
        cr3: int,
        *,
        name: str = "",
        five_level: bool = False,
    ):
        self._physical = physical_layer
        self._cr3 = cr3
        self._walker = PageTableWalker(physical_layer, five_level=five_level)
        self._name = name or f"virtual@0x{cr3:x}"
        self._mappings: list[VirtualMapping] | None = None

    def _ensure_mappings(self) -> list[VirtualMapping]:
        if self._mappings is None:
            self._mappings = sorted(
                self._walker.walk_all_mappings(self._cr3),
                key=lambda m: m.virtual_start,
            )
        return self._mappings

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        """Read *length* bytes starting at virtual address *offset*."""
        result = bytearray()
        remaining = length
        va = offset

        while remaining > 0:
            try:
                tr = self._walker.translate(self._cr3, va)
            except TranslationError:
                if pad:
                    # Pad to next page boundary
                    chunk = min(remaining, PAGE_4K - (va % PAGE_4K))
                    result.extend(b"\x00" * chunk)
                    va += chunk
                    remaining -= chunk
                    continue
                raise

            page_offset = va % tr.page_size
            available = tr.page_size - page_offset
            chunk = min(remaining, available)

            try:
                data = self._physical.read(tr.physical_address, chunk, pad=pad)
            except Exception:
                if pad:
                    data = b"\x00" * chunk
                else:
                    raise

            result.extend(data)
            va += chunk
            remaining -= chunk

        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("Virtual address layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        try:
            self._walker.translate(self._cr3, offset)
            return True
        except TranslationError:
            return False

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        """Scan all mapped virtual pages."""
        mappings = self._ensure_mappings()
        total = len(mappings)
        for i, mapping in enumerate(mappings):
            try:
                data = self._physical.read(
                    mapping.physical_start, mapping.size, pad=True
                )
            except Exception:
                continue
            for result in scanner.scan(data, offset=mapping.virtual_start):
                yield result
            if progress_callback and total > 0:
                progress_callback(i / total)

    @property
    def minimum_address(self) -> int:
        mappings = self._ensure_mappings()
        if mappings:
            return mappings[0].virtual_start
        return 0

    @property
    def maximum_address(self) -> int:
        mappings = self._ensure_mappings()
        if mappings:
            last = mappings[-1]
            return last.virtual_start + last.size
        return 0

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name)

    @property
    def cr3(self) -> int:
        return self._cr3

    @property
    def walker(self) -> PageTableWalker:
        return self._walker

    def get_mappings(self) -> list[VirtualMapping]:
        """Return all resolved virtual-to-physical mappings."""
        return list(self._ensure_mappings())
