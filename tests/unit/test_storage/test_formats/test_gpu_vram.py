"""Tests for the GPU VRAM dump layer."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.storage.formats.gpu_vram import GPUVRAMLayer


class TestGPUVRAM:
    def test_flat_round_trip(self, tmp_path: Path) -> None:
        data = bytes(range(256))
        dump = tmp_path / "vram.bin"
        dump.write_bytes(data)
        with GPUVRAMLayer(dump) as layer:
            assert layer.read(0, len(data)) == data
            assert layer.read(16, 32) == data[16:48]
            assert layer.vendor == "unknown"
            assert layer.minimum_address == 0
            assert layer.maximum_address == len(data) - 1

    def test_vendor_metadata(self, tmp_path: Path) -> None:
        dump = tmp_path / "v.bin"
        dump.write_bytes(b"\x00" * 16)
        with GPUVRAMLayer(dump, vendor="nvidia") as layer:
            assert layer.vendor == "nvidia"
            assert "nvidia" in layer.metadata.name

    def test_custom_name_overrides_vendor_default(self, tmp_path: Path) -> None:
        dump = tmp_path / "v.bin"
        dump.write_bytes(b"\x00" * 16)
        with GPUVRAMLayer(dump, vendor="amd", name="pinned-bo") as layer:
            assert layer.metadata.name == "pinned-bo"
            assert layer.vendor == "amd"

    def test_pad_nopad(self, tmp_path: Path) -> None:
        dump = tmp_path / "p.bin"
        dump.write_bytes(b"\xAB" * 16)
        with GPUVRAMLayer(dump) as layer:
            assert layer.read(12, 8) == b"\xAB" * 4
            assert layer.read(12, 8, pad=True) == b"\xAB" * 4 + b"\x00" * 4
            assert layer.read(100, 4) == b""
            assert layer.read(100, 4, pad=True) == b"\x00" * 4

    def test_write_raises(self, tmp_path: Path) -> None:
        dump = tmp_path / "ro.bin"
        dump.write_bytes(b"\x00" * 8)
        with GPUVRAMLayer(dump) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")

    def test_is_valid(self, tmp_path: Path) -> None:
        dump = tmp_path / "b.bin"
        dump.write_bytes(b"\x00" * 32)
        with GPUVRAMLayer(dump) as layer:
            assert layer.is_valid(0, 32)
            assert not layer.is_valid(0, 33)
            assert not layer.is_valid(-1, 1)
