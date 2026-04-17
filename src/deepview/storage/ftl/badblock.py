"""Bad-block-remapping FTL translator.

This is the trivial fallback translator: LBA *n* maps to the *n*-th good
physical block. Bad blocks are skipped in order. When ``bad_blocks`` is not
supplied explicitly the translator scans the spare-area bad-marker regions
of the first two pages of every block (the conventional Linux MTD location)
and marks any block whose marker byte is non-0xFF as bad.
"""
from __future__ import annotations

from collections.abc import Iterator

from deepview.interfaces.ftl import FTLTranslator, LBAMapping, PhysicalPage
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry
from deepview.storage.manager import StorageError


class BadBlockRemapTranslator(FTLTranslator):
    """Identity mapping that skips known-bad blocks."""

    name = "badblock"

    def __init__(
        self,
        geometry: NANDGeometry,
        bad_blocks: set[int] | None = None,
    ) -> None:
        self._geometry = geometry
        self._bad_blocks: set[int] = set(bad_blocks) if bad_blocks is not None else set()
        self._explicit_bad_blocks = bad_blocks is not None
        self._map: dict[int, LBAMapping] = {}
        self._good_block_order: list[int] = []
        self._built = False

    # ------------------------------------------------------------------
    # FTLTranslator protocol
    # ------------------------------------------------------------------

    @classmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometry) -> bool:  # type: ignore[override]
        # Trivial fallback: always applicable.
        return True

    def build_map(
        self,
        layer: DataLayer | None = None,
        geometry: NANDGeometry | None = None,
    ) -> Iterator[LBAMapping]:
        geo = geometry or self._geometry
        if not self._explicit_bad_blocks and layer is not None:
            self._scan_bad_markers(layer, geo)
        self._good_block_order = [
            b for b in range(geo.blocks) if b not in self._bad_blocks
        ]
        self._map.clear()
        total_page_size = geo.total_page_size
        lba = 0
        for good_block in self._good_block_order:
            for page in range(geo.pages_per_block):
                page_index = good_block * geo.pages_per_block + page
                data_offset = page_index * total_page_size
                spare_offset = data_offset + geo.page_size
                phys = PhysicalPage(
                    block=good_block,
                    page=page,
                    data_offset=data_offset,
                    spare_offset=spare_offset,
                    data_size=geo.page_size,
                    spare_size=geo.spare_size,
                )
                mapping = LBAMapping(lba=lba, physical=phys, bad=False)
                self._map[lba] = mapping
                yield mapping
                lba += 1
        self._built = True

    def translate(self, lba: int) -> LBAMapping | None:
        if not self._built:
            for _ in self.build_map():
                pass
        return self._map.get(lba)

    def logical_size(self) -> int:
        if not self._built:
            for _ in self.build_map():
                pass
        return len(self._map) * self._geometry.page_size

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _scan_bad_markers(self, layer: DataLayer, geometry: NANDGeometry) -> None:
        """Scan first and second page of each block for a non-0xFF bad marker."""
        spare_layout = geometry.spare_layout
        if spare_layout is None:
            return
        markers = spare_layout.regions_of("bad_marker")
        if not markers:
            return
        marker = markers[0]
        total_page_size = geometry.total_page_size
        try:
            for block in range(geometry.blocks):
                block_base = block * geometry.pages_per_block * total_page_size
                for page in (0, 1):
                    if page >= geometry.pages_per_block:
                        break
                    page_base = block_base + page * total_page_size
                    spare_base = page_base + geometry.page_size
                    raw = layer.read(
                        spare_base + marker.offset, marker.length, pad=True
                    )
                    if not raw:
                        continue
                    if any(b != 0xFF for b in raw):
                        self._bad_blocks.add(block)
                        break
        except Exception as exc:  # pragma: no cover - defensive
            raise StorageError(f"bad-block scan failed: {exc}") from exc
