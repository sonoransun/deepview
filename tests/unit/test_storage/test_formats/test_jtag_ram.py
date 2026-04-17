"""Tests for the JTAG RAM layer (flat + multi-region with JSON sidecar)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepview.storage.formats.jtag_ram import JTAGRAMLayer


class TestJTAGRAMFlat:
    def test_flat_round_trip(self, tmp_path: Path) -> None:
        data = bytes(range(128)) * 2
        dump = tmp_path / "dump.bin"
        dump.write_bytes(data)
        with JTAGRAMLayer(dump) as layer:
            assert layer.is_multi_region is False
            assert layer.read(0, len(data)) == data

    def test_pad_nopad(self, tmp_path: Path) -> None:
        dump = tmp_path / "f.bin"
        dump.write_bytes(b"\xEE" * 16)
        with JTAGRAMLayer(dump) as layer:
            assert layer.read(200, 8) == b""
            assert layer.read(200, 8, pad=True) == b"\x00" * 8


class TestJTAGRAMMultiRegion:
    def _build_two_region_dump(self, tmp_path: Path) -> Path:
        """Region A @ VA 0x20000000 size 0x40 (file 0..0x40),
        Region B @ VA 0x08000000 size 0x20 (file 0x40..0x60)."""
        a = b"\xAA" * 0x40
        b = b"\xBB" * 0x20
        body = a + b
        dump = tmp_path / "j.bin"
        dump.write_bytes(body)
        sidecar = dump.with_suffix(".json")
        sidecar.write_text(
            json.dumps(
                [
                    {
                        "offset": 0x20000000,
                        "size": 0x40,
                        "name": "SRAM",
                        "file_offset": 0,
                    },
                    {
                        "offset": 0x08000000,
                        "size": 0x20,
                        "name": "Flash",
                        "file_offset": 0x40,
                    },
                ]
            )
        )
        return dump

    def test_region_aware_read(self, tmp_path: Path) -> None:
        dump = self._build_two_region_dump(tmp_path)
        with JTAGRAMLayer(dump) as layer:
            assert layer.is_multi_region is True
            # Regions are sorted by VA: 0x08000000 first, 0x20000000 second.
            assert [r.name for r in layer.regions] == ["Flash", "SRAM"]
            assert layer.read(0x20000000, 0x40) == b"\xAA" * 0x40
            assert layer.read(0x08000000, 0x20) == b"\xBB" * 0x20
            # Partial reads inside a region.
            assert layer.read(0x20000010, 16) == b"\xAA" * 16

    def test_gap_padding(self, tmp_path: Path) -> None:
        dump = self._build_two_region_dump(tmp_path)
        with JTAGRAMLayer(dump) as layer:
            # Read in a completely unmapped address; pad returns zeros.
            assert layer.read(0x90000000, 8) == b""
            assert layer.read(0x90000000, 8, pad=True) == b"\x00" * 8

    def test_is_valid_multi(self, tmp_path: Path) -> None:
        dump = self._build_two_region_dump(tmp_path)
        with JTAGRAMLayer(dump) as layer:
            assert layer.is_valid(0x20000000, 0x40)
            assert not layer.is_valid(0x20000000, 0x41)
            assert not layer.is_valid(0x10000000, 1)

    def test_min_max_addresses(self, tmp_path: Path) -> None:
        dump = self._build_two_region_dump(tmp_path)
        with JTAGRAMLayer(dump) as layer:
            assert layer.minimum_address == 0x08000000
            assert layer.maximum_address == 0x20000000 + 0x40 - 1


class TestJTAGRAMMisc:
    def test_write_raises(self, tmp_path: Path) -> None:
        dump = tmp_path / "j.bin"
        dump.write_bytes(b"\x00" * 8)
        with JTAGRAMLayer(dump) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")

    def test_explicit_sidecar_path(self, tmp_path: Path) -> None:
        dump = tmp_path / "d.bin"
        dump.write_bytes(b"\xCC" * 16)
        side = tmp_path / "custom_map.json"
        side.write_text(
            json.dumps(
                [
                    {"offset": 0x1000, "size": 16, "name": "r", "file_offset": 0}
                ]
            )
        )
        with JTAGRAMLayer(dump, sidecar=side) as layer:
            assert layer.is_multi_region is True
            assert layer.read(0x1000, 16) == b"\xCC" * 16
