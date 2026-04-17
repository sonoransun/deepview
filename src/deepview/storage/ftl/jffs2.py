"""JFFS2 node-magic translator.

JFFS2 is *not* a block-remapping FTL — it is a log-structured filesystem
where nodes are written sequentially across the chip. This translator is a
best-effort approximation: it scans for the node magic ``0x1985`` (bytes
``\\x85\\x19`` little-endian) and exposes each node as a sequential LBA so
downstream code can walk node data in write order. Reconstructing file
contents requires a proper JFFS2 parser and is out of scope here.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator

from deepview.interfaces.ftl import FTLTranslator, LBAMapping, PhysicalPage
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry

JFFS2_MAGIC_LE = b"\x85\x19"
JFFS2_NODE_HEADER_SIZE = 12  # magic(2) + nodetype(2) + totlen(4) + hdr_crc(4)


class JFFS2Translator(FTLTranslator):
    """Scan JFFS2 node headers and expose each as a sequential LBA."""

    name = "jffs2"

    def __init__(self, geometry: NANDGeometry) -> None:
        self._geometry = geometry
        self._map: dict[int, LBAMapping] = {}
        self._built = False

    @classmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometry) -> bool:  # type: ignore[override]
        try:
            scan_bytes = min(16 * geometry.page_size, 16 * 2048)
            raw = layer.read(0, scan_bytes, pad=True)
        except Exception:
            return False
        return JFFS2_MAGIC_LE in raw

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
        total_bytes = geo.blocks * geo.pages_per_block * total_page_size
        lba = 0
        offset = 0
        while offset + JFFS2_NODE_HEADER_SIZE <= total_bytes:
            header = layer.read(offset, JFFS2_NODE_HEADER_SIZE, pad=True)
            if len(header) < JFFS2_NODE_HEADER_SIZE:
                break
            if header[:2] != JFFS2_MAGIC_LE:
                offset += 4  # JFFS2 nodes are 4-byte aligned
                continue
            try:
                totlen = struct.unpack("<I", header[4:8])[0]
            except struct.error:
                offset += 4
                continue
            if totlen < JFFS2_NODE_HEADER_SIZE or totlen > total_bytes - offset:
                offset += 4
                continue
            page_index = offset // total_page_size
            block = page_index // geo.pages_per_block
            page = page_index % geo.pages_per_block
            phys = PhysicalPage(
                block=block,
                page=page,
                data_offset=offset,
                spare_offset=offset + geo.page_size,
                data_size=min(totlen, geo.page_size),
                spare_size=geo.spare_size,
            )
            mapping = LBAMapping(lba=lba, physical=phys, bad=False)
            self._map[lba] = mapping
            yield mapping
            lba += 1
            # Align to 4 bytes after the node.
            offset += (totlen + 3) & ~3
        self._built = True

    def translate(self, lba: int) -> LBAMapping | None:
        return self._map.get(lba)

    def logical_size(self) -> int:
        if not self._map:
            return 0
        return len(self._map) * self._geometry.page_size
