"""Tests for the SPI-flash dump layer."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.storage.formats.spi_flash import SPIFlashLayer


class TestSPIFlash:
    def test_flat_round_trip(self, tmp_path: Path) -> None:
        data = bytes(range(256)) * 2
        dump = tmp_path / "spi.bin"
        dump.write_bytes(data)
        with SPIFlashLayer(dump) as layer:
            assert layer.read(0, len(data)) == data
            assert layer.total_size == len(data)
            assert layer.sfdp_detected is False
            assert layer.minimum_address == 0
            assert layer.maximum_address == len(data) - 1

    def test_sfdp_detected(self, tmp_path: Path) -> None:
        # Forge a small SFDP header (don't bother with a real density DWORD).
        buf = bytearray(256)
        buf[0:4] = b"SFDP"
        dump = tmp_path / "sfdp.bin"
        dump.write_bytes(bytes(buf))
        with SPIFlashLayer(dump) as layer:
            assert layer.sfdp_detected is True

    def test_sfdp_density_decoded(self, tmp_path: Path) -> None:
        """When bit 31 is clear, density = flash_size_bits - 1."""
        buf = bytearray(0x100)
        buf[0:4] = b"SFDP"
        # 16 Mbit = 2_097_152 B = 16_777_216 bits; density = bits-1.
        density = (16 * 1024 * 1024) - 1
        buf[0x34:0x38] = density.to_bytes(4, "little")
        dump = tmp_path / "sized.bin"
        dump.write_bytes(bytes(buf))
        with SPIFlashLayer(dump) as layer:
            assert layer.sfdp_detected is True
            assert layer.total_size == 16 * 1024 * 1024 // 8

    def test_pad_nopad(self, tmp_path: Path) -> None:
        dump = tmp_path / "p.bin"
        dump.write_bytes(b"\x11" * 16)
        with SPIFlashLayer(dump) as layer:
            assert layer.read(12, 8) == b"\x11" * 4
            assert layer.read(12, 8, pad=True) == b"\x11" * 4 + b"\x00" * 4
            assert layer.read(200, 4) == b""
            assert layer.read(200, 4, pad=True) == b"\x00" * 4

    def test_sector_size_default(self, tmp_path: Path) -> None:
        dump = tmp_path / "s.bin"
        dump.write_bytes(b"\x00" * 8)
        with SPIFlashLayer(dump) as layer:
            assert layer.sector_size == 4096

    def test_invalid_sector_size(self, tmp_path: Path) -> None:
        dump = tmp_path / "s.bin"
        dump.write_bytes(b"\x00" * 8)
        with pytest.raises(ValueError):
            SPIFlashLayer(dump, sector_size=0)

    def test_write_raises(self, tmp_path: Path) -> None:
        dump = tmp_path / "r.bin"
        dump.write_bytes(b"\x00" * 4)
        with SPIFlashLayer(dump) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")
