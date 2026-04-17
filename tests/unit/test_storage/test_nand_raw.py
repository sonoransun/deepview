"""Tests for ``RawNANDLayer`` — flat-file and geometry-aware behaviour."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.types import LayerMetadata
from deepview.interfaces.ftl import PhysicalPage
from deepview.storage.formats.nand_raw import RawNANDLayer
from deepview.storage.geometry import NANDGeometry
from deepview.storage.manager import StorageError

from ._fixtures import build_nand_dump


# ---------------------------------------------------------------------------
# Flat-file mode (no geometry)
# ---------------------------------------------------------------------------


class TestFlatFileMode:
    """A RawNANDLayer constructed without a geometry is a raw byte window."""

    def test_read_bytes_match_file_contents(self, tmp_path: Path) -> None:
        data = b"".join(bytes([i & 0xFF]) * 16 for i in range(32))
        path = tmp_path / "dump.bin"
        path.write_bytes(data)

        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.read(0, 16) == data[:16]
            assert layer.read(16, 16) == data[16:32]
            assert layer.read(len(data) - 8, 8) == data[-8:]

    def test_maximum_address_is_last_byte(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\xAA" * 100)
        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.minimum_address == 0
            assert layer.maximum_address == 99

    def test_is_valid_bounds(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\x00" * 64)
        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.is_valid(0, 64)
            assert layer.is_valid(63, 1)
            assert not layer.is_valid(64, 1)
            assert not layer.is_valid(-1, 1)
            assert not layer.is_valid(0, 65)

    def test_metadata_uses_custom_name(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\x00" * 32)
        with RawNANDLayer(path, geometry=None, name="chip-A") as layer:
            meta = layer.metadata
            assert isinstance(meta, LayerMetadata)
            assert meta.name == "chip-A"
            assert meta.minimum_address == 0
            assert meta.maximum_address == 31

    def test_metadata_default_name(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\x00" * 4)
        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.metadata.name == "nand_raw"

    def test_iter_pages_without_geometry_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\x00" * 32)
        with RawNANDLayer(path, geometry=None) as layer:
            with pytest.raises(StorageError):
                next(iter(layer.iter_pages()))

    def test_write_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\x00" * 8)
        with RawNANDLayer(path, geometry=None) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")


# ---------------------------------------------------------------------------
# Out-of-bounds / padding semantics
# ---------------------------------------------------------------------------


class TestBoundsAndPadding:
    def test_out_of_bounds_returns_empty_by_default(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\xAA" * 16)
        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.read(100, 8) == b""

    def test_out_of_bounds_with_pad_returns_zeros(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\xAA" * 16)
        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.read(100, 8, pad=True) == b"\x00" * 8

    def test_partial_read_pad_extends_with_zeros(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\xAA" * 10)
        with RawNANDLayer(path, geometry=None) as layer:
            result = layer.read(8, 8, pad=True)
            assert result == b"\xAA\xAA" + b"\x00" * 6

    def test_partial_read_without_pad_truncates(self, tmp_path: Path) -> None:
        path = tmp_path / "dump.bin"
        path.write_bytes(b"\xAA" * 10)
        with RawNANDLayer(path, geometry=None) as layer:
            assert layer.read(8, 8) == b"\xAA\xAA"


# ---------------------------------------------------------------------------
# Geometry-aware mode
# ---------------------------------------------------------------------------


PAGE_SIZE = 512
SPARE_SIZE = 16
PAGES_PER_BLOCK = 4
BLOCKS = 2
TOTAL_PAGES = PAGES_PER_BLOCK * BLOCKS


def _make_geometry() -> NANDGeometry:
    return NANDGeometry(
        page_size=PAGE_SIZE,
        spare_size=SPARE_SIZE,
        pages_per_block=PAGES_PER_BLOCK,
        blocks=BLOCKS,
    )


class TestGeometryMode:
    def test_iter_pages_yields_expected_count(self, tmp_path: Path) -> None:
        path = tmp_path / "nand.bin"
        build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)

        with RawNANDLayer(path, geometry=_make_geometry()) as layer:
            pages = list(layer.iter_pages())

        assert len(pages) == TOTAL_PAGES

    def test_iter_pages_slices_have_correct_sizes_and_content(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "nand.bin"
        build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)

        with RawNANDLayer(path, geometry=_make_geometry()) as layer:
            for index, (meta, data, spare) in enumerate(layer.iter_pages()):
                assert isinstance(meta, PhysicalPage)
                assert meta.data_size == PAGE_SIZE
                assert meta.spare_size == SPARE_SIZE
                assert len(data) == PAGE_SIZE
                assert len(spare) == SPARE_SIZE
                # Page header encodes the page index.
                assert int.from_bytes(data[:4], "big") == index
                # Spare is the fixture's spare_fill.
                assert spare == b"\xCD" * SPARE_SIZE

    def test_iter_pages_block_and_page_numbering(self, tmp_path: Path) -> None:
        path = tmp_path / "nand.bin"
        build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)

        with RawNANDLayer(path, geometry=_make_geometry()) as layer:
            metas = [m for m, _d, _s in layer.iter_pages()]

        for index, meta in enumerate(metas):
            assert meta.block == index // PAGES_PER_BLOCK
            assert meta.page == index % PAGES_PER_BLOCK

    def test_iter_pages_offsets_are_interleaved(self, tmp_path: Path) -> None:
        path = tmp_path / "nand.bin"
        build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)
        total_page = PAGE_SIZE + SPARE_SIZE

        with RawNANDLayer(path, geometry=_make_geometry()) as layer:
            for index, (meta, _data, _spare) in enumerate(layer.iter_pages()):
                assert meta.data_offset == index * total_page
                assert meta.spare_offset == index * total_page + PAGE_SIZE

    def test_read_covers_interleaved_bytes(self, tmp_path: Path) -> None:
        """read() must return the interleaved data+OOB bytes verbatim."""
        path = tmp_path / "nand.bin"
        expected = build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)

        with RawNANDLayer(path, geometry=_make_geometry()) as layer:
            # The whole file read back.
            whole = layer.read(0, len(expected))
            assert whole == expected

    def test_round_trip_page_bytes_match_read(self, tmp_path: Path) -> None:
        """(data || spare) yielded by iter_pages equals layer.read() of the
        same byte range — this is the core "read doesn't extract, it returns
        the raw interleaved stream" guarantee."""
        path = tmp_path / "nand.bin"
        build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)
        total_page = PAGE_SIZE + SPARE_SIZE

        with RawNANDLayer(path, geometry=_make_geometry()) as layer:
            for index, (_meta, data, spare) in enumerate(layer.iter_pages()):
                raw_window = layer.read(index * total_page, total_page)
                assert raw_window == data + spare

    def test_partial_trailing_page_is_skipped(self, tmp_path: Path) -> None:
        """If the file is shorter than the geometry claims, iter_pages stops
        at the last complete page rather than yielding a truncated one."""
        path = tmp_path / "nand.bin"
        # Claim 4 pages worth but only write 3.
        geom = NANDGeometry(
            page_size=PAGE_SIZE,
            spare_size=SPARE_SIZE,
            pages_per_block=4,
            blocks=1,
        )
        build_nand_dump(path, 3, PAGE_SIZE, SPARE_SIZE)

        with RawNANDLayer(path, geometry=geom) as layer:
            pages = list(layer.iter_pages())

        assert len(pages) == 3

    def test_geometry_property_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "nand.bin"
        build_nand_dump(path, TOTAL_PAGES, PAGE_SIZE, SPARE_SIZE)
        geom = _make_geometry()
        with RawNANDLayer(path, geometry=geom) as layer:
            assert layer.geometry is geom
