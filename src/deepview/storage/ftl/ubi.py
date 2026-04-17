"""UBI (Unsorted Block Images) translator.

Parses the UBI erase-counter (EC) header and volume-ID (VID) header at the
start of every physical erase block and uses the VID header's ``lnum`` to
build a logical-erase-block-indexed mapping.

Only volume 0 is exposed in the initial cut; multi-volume support requires
threading the selected ``vol_id`` through the translator API, which the
wider FTL ABC does not yet expose. On any parse failure the translator
falls back to an identity mapping so composition doesn't explode.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator

from deepview.interfaces.ftl import FTLTranslator, LBAMapping, PhysicalPage
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry

UBI_EC_HDR_MAGIC = b"UBI#"
UBI_VID_HDR_MAGIC = b"UBI!"
UBI_EC_HDR_SIZE = 64
UBI_VID_HDR_SIZE = 64


class UBITranslator(FTLTranslator):
    """Decode UBI EC+VID headers to build a logical-erase-block map."""

    name = "ubi"

    def __init__(self, geometry: NANDGeometry, volume_id: int = 0) -> None:
        self._geometry = geometry
        self._volume_id = volume_id
        self._map: dict[int, LBAMapping] = {}
        self._built = False

    # ------------------------------------------------------------------
    # FTLTranslator protocol
    # ------------------------------------------------------------------

    @classmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometry) -> bool:  # type: ignore[override]
        try:
            total_page_size = geometry.total_page_size
            block_size = geometry.pages_per_block * total_page_size
            for block in range(geometry.blocks):
                header = layer.read(block * block_size, 4, pad=True)
                if header == UBI_EC_HDR_MAGIC:
                    return True
        except Exception:
            return False
        return False

    def build_map(
        self,
        layer: DataLayer | None = None,
        geometry: NANDGeometry | None = None,
    ) -> Iterator[LBAMapping]:
        geo = geometry or self._geometry
        if layer is None:
            return
        self._map.clear()
        total_page_size = geo.total_page_size
        block_size = geo.pages_per_block * total_page_size
        for block in range(geo.blocks):
            block_base = block * block_size
            ec_hdr = layer.read(block_base, UBI_EC_HDR_SIZE, pad=True)
            if len(ec_hdr) < UBI_EC_HDR_SIZE or ec_hdr[:4] != UBI_EC_HDR_MAGIC:
                # Fall back to identity mapping for this block.
                yield self._identity_mapping(geo, block, lnum=block)
                continue
            try:
                vid_hdr_offset = struct.unpack(">I", ec_hdr[16:20])[0]
                data_offset = struct.unpack(">I", ec_hdr[20:24])[0]
            except struct.error:
                yield self._identity_mapping(geo, block, lnum=block)
                continue
            vid_abs = block_base + vid_hdr_offset
            vid_hdr = layer.read(vid_abs, UBI_VID_HDR_SIZE, pad=True)
            if len(vid_hdr) < UBI_VID_HDR_SIZE or vid_hdr[:4] != UBI_VID_HDR_MAGIC:
                yield self._identity_mapping(geo, block, lnum=block)
                continue
            try:
                vol_id = struct.unpack(">I", vid_hdr[8:12])[0]
                lnum = struct.unpack(">I", vid_hdr[12:16])[0]
            except struct.error:
                yield self._identity_mapping(geo, block, lnum=block)
                continue
            if vol_id != self._volume_id:
                # Skip entries that belong to other volumes.
                continue
            first_data_page = data_offset // total_page_size
            phys_data_offset = block_base + first_data_page * total_page_size
            phys = PhysicalPage(
                block=block,
                page=first_data_page,
                data_offset=phys_data_offset,
                spare_offset=phys_data_offset + geo.page_size,
                data_size=geo.page_size,
                spare_size=geo.spare_size,
            )
            mapping = LBAMapping(lba=lnum, physical=phys, bad=False)
            self._map[lnum] = mapping
            yield mapping
        self._built = True

    def translate(self, lba: int) -> LBAMapping | None:
        return self._map.get(lba)

    def logical_size(self) -> int:
        if not self._map:
            return 0
        return (max(self._map) + 1) * self._geometry.page_size

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _identity_mapping(
        self, geometry: NANDGeometry, block: int, lnum: int
    ) -> LBAMapping:
        total_page_size = geometry.total_page_size
        block_size = geometry.pages_per_block * total_page_size
        data_offset = block * block_size
        phys = PhysicalPage(
            block=block,
            page=0,
            data_offset=data_offset,
            spare_offset=data_offset + geometry.page_size,
            data_size=geometry.page_size,
            spare_size=geometry.spare_size,
        )
        mapping = LBAMapping(lba=lnum, physical=phys, bad=False)
        self._map[lnum] = mapping
        return mapping
