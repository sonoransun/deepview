"""eMMC hint-driven translator.

eMMC chips expose a flat LBA-addressable surface; the internal FTL is
vendor-proprietary and opaque. This translator is identity-by-default and
uses an optional ``ext_csd.json`` sidecar to label regions (enhanced user
data area, boot partition, etc.) for downstream diagnostics. Future
versions may stretch LBAs across partition boundaries; at present the
mapping is 1:1.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from deepview.interfaces.ftl import FTLTranslator, LBAMapping, PhysicalPage
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry


class EMMCHintTranslator(FTLTranslator):
    """Identity translator with optional ``ext_csd.json`` sidecar hints."""

    name = "emmc_hints"

    def __init__(
        self,
        geometry: NANDGeometry,
        ext_csd_path: Path | None = None,
    ) -> None:
        self._geometry = geometry
        self._ext_csd: dict[str, object] = {}
        if ext_csd_path is not None:
            try:
                text = ext_csd_path.read_text(encoding="utf-8")
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    self._ext_csd = parsed
            except (OSError, json.JSONDecodeError):
                self._ext_csd = {}
        self._map: dict[int, LBAMapping] = {}
        self._built = False

    @classmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometry) -> bool:  # type: ignore[override]
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
            total_page_size = geo.total_page_size
            total_pages = geo.blocks * geo.pages_per_block
            if lba < 0 or lba >= total_pages:
                return None
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
    def ext_csd(self) -> dict[str, object]:
        return dict(self._ext_csd)
