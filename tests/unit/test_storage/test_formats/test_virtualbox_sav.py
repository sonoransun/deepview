"""Tests for the VirtualBox SSM ``.sav`` layer."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.exceptions import FormatError
from deepview.storage.formats.virtualbox_sav import VirtualBoxSavLayer


def _build_ssm(path: Path, ram_bytes: bytes) -> None:
    """Write a synthetic SSM file.

    We prefix a small SSM header, then the RAM bytes as a flat payload.
    The heuristic in ``VirtualBoxSavLayer`` will fall back to flat mode,
    which is the documented passthrough behaviour we want to test here.
    """
    header = b"SSM" + b"\x00" * 13  # 16-byte pseudo header
    path.write_bytes(header + ram_bytes)


class TestVirtualBoxSav:
    def test_flat_read_round_trip(self, tmp_path: Path) -> None:
        ram = bytes(range(256)) * 2  # 512 B
        sav = tmp_path / "vm.sav"
        _build_ssm(sav, ram)

        with VirtualBoxSavLayer(sav) as layer:
            # In flat-passthrough mode, the "RAM" is the whole file including
            # our 16-byte fake header — which is what the documented
            # degradation states. Tests pin that behaviour.
            full = layer.read(0, layer.maximum_address + 1)
            assert full.startswith(b"SSM")
            # The bytes we wrote after the header come through identically.
            assert ram in full

    def test_partial_and_bounds(self, tmp_path: Path) -> None:
        ram = b"\xEE" * 128
        sav = tmp_path / "vm.sav"
        _build_ssm(sav, ram)
        with VirtualBoxSavLayer(sav) as layer:
            size = layer.maximum_address + 1
            assert size == 16 + len(ram)
            assert layer.is_valid(0, size)
            assert not layer.is_valid(size, 1)
            assert layer.read(size, 32) == b""
            assert layer.read(size, 32, pad=True) == b"\x00" * 32

    def test_bad_magic_raises(self, tmp_path: Path) -> None:
        sav = tmp_path / "bad.sav"
        sav.write_bytes(b"NOPE" + b"\x00" * 60)
        with pytest.raises(FormatError):
            VirtualBoxSavLayer(sav)

    def test_write_raises(self, tmp_path: Path) -> None:
        sav = tmp_path / "ro.sav"
        _build_ssm(sav, b"\x01" * 16)
        with VirtualBoxSavLayer(sav) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")

    def test_metadata_marks_flat_fallback(self, tmp_path: Path) -> None:
        sav = tmp_path / "vm.sav"
        _build_ssm(sav, b"\x00" * 32)
        with VirtualBoxSavLayer(sav, name="custom") as layer:
            # With the synthetic minimal header, the parser falls back to
            # flat mode and the metadata name should reflect that.
            assert layer.metadata.name.startswith("custom")
            assert "flat" in layer.metadata.name
            assert layer.parsed_ram is False
