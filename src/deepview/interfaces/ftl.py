from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from deepview.interfaces.layer import DataLayer


@dataclass(frozen=True)
class PhysicalPage:
    """A single physical NAND page with byte offsets into the chip dump."""

    block: int
    page: int
    data_offset: int
    spare_offset: int
    data_size: int
    spare_size: int


@dataclass(frozen=True)
class LBAMapping:
    """A logical-block-address to physical-page mapping produced by an FTL."""

    lba: int
    physical: PhysicalPage
    bad: bool = False


class FTLTranslator(ABC):
    """Flash Translation Layer: maps logical LBAs to physical NAND pages."""

    name: str = ""

    @classmethod
    @abstractmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometryProto) -> bool:
        """Return ``True`` when this translator recognises the on-flash layout."""

    @abstractmethod
    def build_map(
        self, layer: DataLayer, geometry: NANDGeometryProto
    ) -> Iterator[LBAMapping]:
        """Walk the chip and emit logical -> physical mappings."""

    @abstractmethod
    def translate(self, lba: int) -> LBAMapping | None:
        """Return the mapping for *lba* or ``None`` if unmapped."""

    def logical_size(self) -> int:
        """Total addressable logical size in bytes; default 0 if unknown."""
        return 0


class NANDGeometryProto:  # pragma: no cover - structural protocol
    """Protocol-style stand-in to avoid an import cycle with storage.geometry."""

    page_size: int
    spare_size: int
    pages_per_block: int
    blocks: int
    planes: int
