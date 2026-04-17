"""Vendor-specific NAND spare-area layout presets.

These are documentation-grade defaults: real hardware varies by part
number, revision, and controller firmware. The presets below reflect
commonly documented arrangements for 64-byte spare areas on 2 KiB page
devices and are sufficient for synthetic fixtures and reverse-engineering
starting points.
"""
from __future__ import annotations

from deepview.storage.geometry import SpareLayout, SpareRegion

__all__ = [
    "SpareLayout",
    "samsung_klm",
    "toshiba_tc58",
    "micron_mt29f",
]


def samsung_klm(spare_size: int = 64) -> SpareLayout:
    """Samsung KLM-family (eMMC/NAND) spare-area preset.

    Bad-block marker at offset 0 (2 bytes), a middle metadata band, and
    four 10-byte ECC fields at the tail covering four 512-byte data
    sub-pages (40 ECC bytes, BCH-style).
    """
    ecc_total = 40
    metadata_offset = 2
    metadata_length = spare_size - metadata_offset - ecc_total
    return SpareLayout(
        name="samsung_klm",
        spare_size=spare_size,
        regions=(
            SpareRegion(offset=0, length=2, kind="bad_marker"),
            SpareRegion(offset=metadata_offset, length=metadata_length, kind="metadata"),
            SpareRegion(offset=spare_size - ecc_total, length=ecc_total, kind="ecc"),
        ),
    )


def toshiba_tc58(spare_size: int = 64) -> SpareLayout:
    """Toshiba TC58-family NAND spare-area preset.

    Bad-block marker at offset 0 (1 byte), a 15-byte metadata/user area,
    then a 48-byte ECC band covering the 2 KiB main page (BCH-style).
    """
    ecc_total = 48
    metadata_offset = 1
    metadata_length = spare_size - metadata_offset - ecc_total
    return SpareLayout(
        name="toshiba_tc58",
        spare_size=spare_size,
        regions=(
            SpareRegion(offset=0, length=1, kind="bad_marker"),
            SpareRegion(offset=metadata_offset, length=metadata_length, kind="metadata"),
            SpareRegion(offset=spare_size - ecc_total, length=ecc_total, kind="ecc"),
        ),
    )


def micron_mt29f(spare_size: int = 64) -> SpareLayout:
    """Micron MT29F-family NAND spare-area preset.

    Bad-block marker at offsets 0-1, ECC at offsets 8-31 (24 bytes,
    covering four 512-byte sub-pages at 6 bytes each), remainder usable
    as metadata / user area (ONFI 1.x-ish convention).
    """
    bad_marker = SpareRegion(offset=0, length=2, kind="bad_marker")
    ecc_offset = 8
    ecc_length = 24
    ecc = SpareRegion(offset=ecc_offset, length=ecc_length, kind="ecc")
    meta_low = SpareRegion(offset=2, length=6, kind="metadata")
    meta_high = SpareRegion(
        offset=ecc_offset + ecc_length,
        length=spare_size - (ecc_offset + ecc_length),
        kind="metadata",
    )
    return SpareLayout(
        name="micron_mt29f",
        spare_size=spare_size,
        regions=(bad_marker, meta_low, ecc, meta_high),
    )
