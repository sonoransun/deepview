from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SpareRegion:
    """A contiguous span of bytes inside a NAND page's spare/OOB area."""

    offset: int
    length: int
    kind: str  # "data" | "ecc" | "metadata" | "bad_marker"


@dataclass(frozen=True)
class SpareLayout:
    """Description of how a NAND chip's spare area is partitioned."""

    name: str
    spare_size: int
    regions: tuple[SpareRegion, ...] = ()

    def regions_of(self, kind: str) -> tuple[SpareRegion, ...]:
        return tuple(r for r in self.regions if r.kind == kind)

    @classmethod
    def onfi(cls, spare_size: int = 64) -> SpareLayout:
        """ONFI default-ish layout: bad-block marker first, ECC at end."""
        return cls(
            name="onfi",
            spare_size=spare_size,
            regions=(
                SpareRegion(offset=0, length=2, kind="bad_marker"),
                SpareRegion(offset=2, length=spare_size - 16, kind="metadata"),
                SpareRegion(offset=spare_size - 14, length=14, kind="ecc"),
            ),
        )

    @classmethod
    def linear_ecc(cls, spare_size: int, ecc_bytes: int) -> SpareLayout:
        """Trivial layout: bad-block marker first byte, ECC at tail."""
        return cls(
            name="linear",
            spare_size=spare_size,
            regions=(
                SpareRegion(offset=0, length=1, kind="bad_marker"),
                SpareRegion(offset=spare_size - ecc_bytes, length=ecc_bytes, kind="ecc"),
            ),
        )


@dataclass(frozen=True)
class NANDGeometry:
    """Physical layout of a NAND chip dump."""

    page_size: int
    spare_size: int
    pages_per_block: int
    blocks: int
    planes: int = 1
    spare_layout: SpareLayout | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def total_page_size(self) -> int:
        return self.page_size + self.spare_size

    @property
    def block_size(self) -> int:
        return self.page_size * self.pages_per_block

    @property
    def total_pages(self) -> int:
        return self.blocks * self.pages_per_block * self.planes

    @property
    def total_size(self) -> int:
        return self.total_pages * self.total_page_size
