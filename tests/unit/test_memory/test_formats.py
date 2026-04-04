"""Tests for memory format layers — RawMemoryLayer and LiMEMemoryLayer."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from deepview.core.exceptions import FormatError
from deepview.memory.formats.lime_format import LIME_HEADER_FMT, LIME_MAGIC, LiMEMemoryLayer
from deepview.memory.formats.raw import RawMemoryLayer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_lime_file(path: Path, ranges: list[tuple[int, int, bytes]]) -> None:
    """Write a synthetic LiME dump.

    *ranges* is a list of ``(start_addr, end_addr, data)`` tuples.
    ``end_addr`` is inclusive (LiME convention), so ``data`` must be
    ``end_addr - start_addr + 1`` bytes long.
    """
    with open(path, "wb") as f:
        for start, end, data in ranges:
            header = struct.pack(LIME_HEADER_FMT, LIME_MAGIC, 1, start, end, 0)
            f.write(header)
            f.write(data)


# ===========================================================================
# RawMemoryLayer
# ===========================================================================


class TestRawMemoryLayerRead:
    """read() behaviour for RawMemoryLayer."""

    def test_raw_read(self, tmp_path: Path) -> None:
        """Read returns the correct slice of data."""
        data = bytes(range(256)) * 4  # 1024 bytes
        dump = tmp_path / "raw.bin"
        dump.write_bytes(data)
        with RawMemoryLayer(dump) as layer:
            assert layer.read(0, 16) == data[:16]
            assert layer.read(100, 10) == data[100:110]

    def test_raw_read_with_padding(self, tmp_path: Path) -> None:
        """read() with pad=True zero-pads when the range extends past EOF."""
        data = b"\xaa" * 64
        dump = tmp_path / "small.bin"
        dump.write_bytes(data)
        with RawMemoryLayer(dump) as layer:
            result = layer.read(60, 16, pad=True)
            assert len(result) == 16
            # First 4 bytes come from file (offsets 60-63), rest should be 0x00.
            assert result[:4] == b"\xaa" * 4
            assert result[4:] == b"\x00" * 12

    def test_raw_read_out_of_bounds(self, tmp_path: Path) -> None:
        """read() at an invalid offset returns empty bytes (no pad)."""
        dump = tmp_path / "tiny.bin"
        dump.write_bytes(b"\xff" * 32)
        with RawMemoryLayer(dump) as layer:
            assert layer.read(1000, 8) == b""

    def test_raw_write_raises(self, tmp_path: Path) -> None:
        """write() always raises NotImplementedError."""
        dump = tmp_path / "rw.bin"
        dump.write_bytes(b"\x00" * 16)
        with RawMemoryLayer(dump) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"\x01")


class TestRawMemoryLayerValidity:
    """is_valid() and property tests."""

    def test_raw_is_valid(self, tmp_path: Path) -> None:
        """is_valid returns True inside bounds, False outside."""
        dump = tmp_path / "valid.bin"
        dump.write_bytes(b"\x00" * 128)
        with RawMemoryLayer(dump) as layer:
            assert layer.is_valid(0) is True
            assert layer.is_valid(127) is True
            assert layer.is_valid(128) is False
            assert layer.is_valid(0, 128) is True
            assert layer.is_valid(0, 129) is False

    def test_raw_properties(self, tmp_path: Path) -> None:
        """minimum_address is 0 and maximum_address equals the file size."""
        data = b"\xab" * 512
        dump = tmp_path / "props.bin"
        dump.write_bytes(data)
        with RawMemoryLayer(dump) as layer:
            assert layer.minimum_address == 0
            assert layer.maximum_address == 512


class TestRawMemoryLayerLifecycle:
    """Context-manager and __del__ cleanup."""

    def test_raw_context_manager(self, tmp_path: Path) -> None:
        """with-statement opens and closes without error."""
        dump = tmp_path / "ctx.bin"
        dump.write_bytes(b"\x00" * 16)
        with RawMemoryLayer(dump) as layer:
            assert layer.read(0, 4) == b"\x00" * 4
        # After exit, the layer should be closed (no leaked fd).

    def test_raw_del_cleanup(self, tmp_path: Path) -> None:
        """Explicit del does not raise."""
        dump = tmp_path / "del.bin"
        dump.write_bytes(b"\x00" * 16)
        layer = RawMemoryLayer(dump)
        layer.read(0, 4)
        del layer  # should not raise


# ===========================================================================
# LiMEMemoryLayer
# ===========================================================================


class TestLiMEMemoryLayerRead:
    """Tests for LiMEMemoryLayer."""

    def test_lime_single_range(self, tmp_path: Path) -> None:
        """A single-range LiME dump can be read back correctly."""
        start_addr = 0x1000
        data = b"\xde\xad\xbe\xef" * 64  # 256 bytes
        end_addr = start_addr + len(data) - 1

        lime_file = tmp_path / "single.lime"
        _build_lime_file(lime_file, [(start_addr, end_addr, data)])

        with LiMEMemoryLayer(lime_file) as layer:
            assert layer.read(start_addr, 4) == b"\xde\xad\xbe\xef"
            assert layer.read(start_addr, len(data)) == data
            assert layer.minimum_address == start_addr
            assert layer.maximum_address == end_addr

    def test_lime_invalid_magic_raises(self, tmp_path: Path) -> None:
        """FormatError when the magic value is wrong."""
        bad_file = tmp_path / "bad_magic.lime"
        # Use wrong magic (0xDEADBEEF instead of 0x4C694D45)
        header = struct.pack(LIME_HEADER_FMT, 0xDEADBEEF, 1, 0, 255, 0)
        bad_file.write_bytes(header + b"\x00" * 256)
        with pytest.raises(FormatError, match="Invalid LiME magic"):
            LiMEMemoryLayer(bad_file)


class TestLiMEMemoryLayerLifecycle:
    """Context-manager and __del__ cleanup for LiME layers."""

    def test_lime_context_manager(self, tmp_path: Path) -> None:
        """with-statement opens and closes without error."""
        start_addr = 0
        data = b"\x41" * 64
        end_addr = start_addr + len(data) - 1

        lime_file = tmp_path / "ctx.lime"
        _build_lime_file(lime_file, [(start_addr, end_addr, data)])

        with LiMEMemoryLayer(lime_file) as layer:
            assert layer.read(0, 4) == b"\x41" * 4

    def test_lime_del_cleanup(self, tmp_path: Path) -> None:
        """Explicit del does not raise."""
        start_addr = 0
        data = b"\x42" * 64
        end_addr = start_addr + len(data) - 1

        lime_file = tmp_path / "del.lime"
        _build_lime_file(lime_file, [(start_addr, end_addr, data)])

        layer = LiMEMemoryLayer(lime_file)
        layer.read(0, 4)
        del layer  # should not raise
