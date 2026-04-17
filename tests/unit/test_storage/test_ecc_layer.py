"""End-to-end ECCDataLayer test: synthetic NAND dump with Hamming ECC.

Each physical page is laid out as ``[data:512][hamming_ecc:3][padding:61]``
with ``spare_size=64``. Two 256-byte chunks share the 6 ECC bytes (3 per
chunk). We then flip one bit in each page's data and verify that
ECCDataLayer transparently corrects the error and reports the right
stats.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("deepview.storage.formats.nand_raw")

from deepview.storage.ecc.base import ECCDataLayer  # noqa: E402
from deepview.storage.ecc.hamming import HammingDecoder  # noqa: E402
from deepview.storage.formats.nand_raw import RawNANDLayer  # noqa: E402
from deepview.storage.geometry import (  # noqa: E402
    NANDGeometry,
    SpareLayout,
    SpareRegion,
)


PAGES = 8
PAGE_SIZE = 512
SPARE_SIZE = 64
CHUNKS_PER_PAGE = 2
ECC_PER_CHUNK = 3
ECC_TOTAL = CHUNKS_PER_PAGE * ECC_PER_CHUNK  # 6


def _spare_layout() -> SpareLayout:
    """ECC at offset 0, six bytes; remainder is padding/metadata."""
    return SpareLayout(
        name="test_layout",
        spare_size=SPARE_SIZE,
        regions=(
            SpareRegion(offset=0, length=ECC_TOTAL, kind="ecc"),
            SpareRegion(offset=ECC_TOTAL, length=SPARE_SIZE - ECC_TOTAL, kind="metadata"),
        ),
    )


def _build_dump(tmp_path: Path, *, flip: bool) -> Path:
    """Write a raw NAND dump whose pages carry Hamming ECC over each
    256-byte half of the 512-byte data area.

    If ``flip`` is True, a single bit is flipped in each page's data
    after the ECC has been computed, so the decoder must correct it.
    """
    decoder = HammingDecoder()
    out = bytearray()
    for page_idx in range(PAGES):
        data = bytearray()
        for chunk_idx in range(CHUNKS_PER_PAGE):
            base = (page_idx * CHUNKS_PER_PAGE + chunk_idx) & 0xFF
            chunk = bytes(((base + i) & 0xFF) for i in range(256))
            data.extend(chunk)
        ecc_blob = bytearray()
        for chunk_idx in range(CHUNKS_PER_PAGE):
            chunk = bytes(data[chunk_idx * 256:(chunk_idx + 1) * 256])
            ecc_blob.extend(decoder.encode(chunk))
        if flip:
            # Flip one bit, distributed so different pages hit different
            # offsets / bit positions to cover the address-decoder space.
            byte_offset = (page_idx * 13) % PAGE_SIZE
            bit_offset = page_idx % 8
            data[byte_offset] ^= 1 << bit_offset
        spare = bytearray(SPARE_SIZE)
        spare[:ECC_TOTAL] = ecc_blob
        out.extend(data)
        out.extend(spare)
    path = tmp_path / "nand.bin"
    path.write_bytes(bytes(out))
    return path


def _geometry() -> NANDGeometry:
    return NANDGeometry(
        page_size=PAGE_SIZE,
        spare_size=SPARE_SIZE,
        pages_per_block=PAGES,
        blocks=1,
        spare_layout=_spare_layout(),
    )


def _expected_logical_bytes() -> bytes:
    """The clean (pre-flip) data concatenated across every page."""
    buf = bytearray()
    for page_idx in range(PAGES):
        for chunk_idx in range(CHUNKS_PER_PAGE):
            base = (page_idx * CHUNKS_PER_PAGE + chunk_idx) & 0xFF
            chunk = bytes(((base + i) & 0xFF) for i in range(256))
            buf.extend(chunk)
    return bytes(buf)


def test_ecc_layer_clean_read(tmp_path: Path) -> None:
    path = _build_dump(tmp_path, flip=False)
    raw = RawNANDLayer(path, geometry=_geometry())
    layer = ECCDataLayer(raw, HammingDecoder(), _geometry())
    assert layer.minimum_address == 0
    assert layer.maximum_address == PAGES * PAGE_SIZE - 1
    assert layer.metadata.name == "ecc:hamming256"

    total = PAGES * PAGE_SIZE
    got = layer.read(0, total)
    assert got == _expected_logical_bytes()

    stats = layer.error_stats()
    assert stats["corrected"] == 0
    assert stats["uncorrectable"] == 0
    assert stats["pages_read"] >= PAGES
    raw.close()


def test_ecc_layer_corrects_single_bit_per_page(tmp_path: Path) -> None:
    path = _build_dump(tmp_path, flip=True)
    raw = RawNANDLayer(path, geometry=_geometry())
    layer = ECCDataLayer(raw, HammingDecoder(), _geometry())

    total = PAGES * PAGE_SIZE
    got = layer.read(0, total)
    assert got == _expected_logical_bytes()

    stats = layer.error_stats()
    assert stats["corrected"] > 0, "expected at least one corrected error"
    assert stats["corrected"] >= PAGES, (
        "each page should have contributed at least one correction"
    )
    assert stats["uncorrectable"] == 0
    raw.close()


def test_ecc_layer_is_valid_and_bounds(tmp_path: Path) -> None:
    path = _build_dump(tmp_path, flip=False)
    raw = RawNANDLayer(path, geometry=_geometry())
    layer = ECCDataLayer(raw, HammingDecoder(), _geometry())
    total = PAGES * PAGE_SIZE
    assert layer.is_valid(0, total) is True
    assert layer.is_valid(total - 1, 1) is True
    assert layer.is_valid(total, 1) is False
    assert layer.is_valid(-1, 1) is False
    raw.close()


def test_ecc_layer_write_is_unsupported(tmp_path: Path) -> None:
    path = _build_dump(tmp_path, flip=False)
    raw = RawNANDLayer(path, geometry=_geometry())
    layer = ECCDataLayer(raw, HammingDecoder(), _geometry())
    with pytest.raises(NotImplementedError):
        layer.write(0, b"\x00")
    raw.close()
