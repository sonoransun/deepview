"""UFS hint-driven translator.

UFS chips expose a flat LBA surface with Unit Descriptors listing
partitions (boot, user data, RPMB, enhanced regions). Like eMMC the
internal FTL is vendor-proprietary; this translator is identity-by-default
and accepts a JSON sidecar describing Unit Descriptors for labelling.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from deepview.interfaces.ftl import FTLTranslator, LBAMapping, PhysicalPage
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry


class UFSTranslator(FTLTranslator):
    """Identity translator with optional UFS Unit Descriptor sidecar hints."""

    name = "ufs"

    def __init__(
        self,
        geometry: NANDGeometry,
        unit_descriptor_path: Path | None = None,
    ) -> None:
        self._geometry = geometry
        self._descriptors: dict[str, object] = {}
        if unit_descriptor_path is not None:
            try:
                text = unit_descriptor_path.read_text(encoding="utf-8")
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    self._descriptors = parsed
            except (OSError, json.JSONDecodeError):
                self._descriptors = {}
        self._map: dict[int, LBAMapping] = {}
        self._built = False

    @classmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometry) -> bool:  # type: ignore[override]
        # Same shape test as eMMC: flat, no OOB.
        return geometry.page_size in (4096, 8192) and geometry.spare_size == 0

    def build_map(
        self,
        layer: DataLayer | None = None,
        geometry: NANDGeometry | None = None,
    ) -> Iterator[LBAMapping]:
        geo = geometry or self._geometry
        self._map.clear()
        total_page_size = geo.total_page_size
        total_pages = geo.blocks * geo.pages_per_block
        for lba in range(total_pages):
            data_offset = lba * total_page_size
            block = lba // geo.pages_per_block
            page = lba % geo.pages_per_block
            phys = PhysicalPage(
                block=block,
                page=page,
                data_offset=data_offset,
                spare_offset=data_offset + geo.page_size,
                data_size=geo.page_size,
                spare_size=geo.spare_size,
            )
            mapping = LBAMapping(lba=lba, physical=phys, bad=False)
            self._map[lba] = mapping
            yield mapping
        self._built = True

    def translate(self, lba: int) -> LBAMapping | None:
        if not self._built:
            geo = self._geometry
            total_pages = geo.blocks * geo.pages_per_block
            if lba < 0 or lba >= total_pages:
                return None
            total_page_size = geo.total_page_size
            data_offset = lba * total_page_size
            block = lba // geo.pages_per_block
            page = lba % geo.pages_per_block
            phys = PhysicalPage(
                block=block,
                page=page,
                data_offset=data_offset,
                spare_offset=data_offset + geo.page_size,
                data_size=geo.page_size,
                spare_size=geo.spare_size,
            )
            return LBAMapping(lba=lba, physical=phys, bad=False)
        return self._map.get(lba)

    def logical_size(self) -> int:
        geo = self._geometry
        return geo.blocks * geo.pages_per_block * geo.page_size

    @property
    def descriptors(self) -> dict[str, object]:
        return dict(self._descriptors)
