"""Tests for the eMMC raw dump layer."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.storage.formats.emmc_raw import EMMCRawLayer


class TestEMMCRaw:
    def test_flat_round_trip(self, tmp_path: Path) -> None:
        data = bytes(range(256)) * 4
        dump = tmp_path / "emmc.img"
        dump.write_bytes(data)
        with EMMCRawLayer(dump) as layer:
            assert layer.read(0, len(data)) == data
            assert layer.read(200, 16) == data[200:216]
            assert layer.minimum_address == 0
            assert layer.maximum_address == len(data) - 1

    def test_pad_nopad(self, tmp_path: Path) -> None:
        dump = tmp_path / "e.img"
        dump.write_bytes(b"\x55" * 16)
        with EMMCRawLayer(dump) as layer:
            assert layer.read(200, 4) == b""
            assert layer.read(200, 4, pad=True) == b"\x00" * 4
            assert layer.read(12, 8) == b"\x55" * 4
            assert layer.read(12, 8, pad=True) == b"\x55" * 4 + b"\x00" * 4

    def test_mbr_signature_detected(self, tmp_path: Path) -> None:
        """A file with 0x55AA at offset 0x1FE should flip has_mbr."""
        buf = bytearray(512)
        buf[0x1FE] = 0x55
        buf[0x1FF] = 0xAA
        dump = tmp_path / "mbr.img"
        dump.write_bytes(bytes(buf))
        with EMMCRawLayer(dump) as layer:
            assert layer.has_mbr is True
            assert layer.has_gpt is False

    def test_gpt_signature_detected(self, tmp_path: Path) -> None:
        buf = bytearray(1024)
        buf[0x200:0x208] = b"EFI PART"
        dump = tmp_path / "gpt.img"
        dump.write_bytes(bytes(buf))
        with EMMCRawLayer(dump) as layer:
            assert layer.has_gpt is True

    def test_boot_offsets_when_large_enough(self, tmp_path: Path) -> None:
        size = 3 * 4 * 1024 * 1024
        dump = tmp_path / "big.img"
        dump.write_bytes(b"\x00" * size)
        with EMMCRawLayer(dump) as layer:
            assert layer.boot1_offset == 0
            assert layer.boot2_offset == 4 * 1024 * 1024
            assert layer.rpmb_offset == 2 * 4 * 1024 * 1024

    def test_boot_offsets_none_for_small_file(self, tmp_path: Path) -> None:
        dump = tmp_path / "small.img"
        dump.write_bytes(b"\x00" * 1024)
        with EMMCRawLayer(dump) as layer:
            assert layer.boot1_offset is None
            assert layer.boot2_offset is None
            assert layer.rpmb_offset is None

    def test_block_size_roundtrip(self, tmp_path: Path) -> None:
        dump = tmp_path / "b.img"
        dump.write_bytes(b"\x00" * 32)
        with EMMCRawLayer(dump, block_size=4096) as layer:
            assert layer.block_size == 4096

    def test_invalid_block_size(self, tmp_path: Path) -> None:
        dump = tmp_path / "z.img"
        dump.write_bytes(b"\x00" * 8)
        with pytest.raises(ValueError):
            EMMCRawLayer(dump, block_size=0)

    def test_write_raises(self, tmp_path: Path) -> None:
        dump = tmp_path / "ro.img"
        dump.write_bytes(b"\x00" * 8)
        with EMMCRawLayer(dump) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")
