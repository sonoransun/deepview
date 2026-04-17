"""Tests for ``CrashDumpLayer``.

Covers both the 64-bit (``PAGEDU64``) full dump and the 32-bit (``PAGE``)
header path. The page runs are laid out immediately after the header, and
each page is filled with a PFN-specific byte so we can round-trip the
read path.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from deepview.core.exceptions import FormatError
from deepview.memory.formats.crashdump import (
    CRASHDUMP_MAGIC32,
    CRASHDUMP_MAGIC64,
    DUMP_TYPE_FULL,
    HEADER_SIZE_32,
    HEADER_SIZE_64,
    PAGE_SIZE,
    CrashDumpLayer,
)

# Keep explicit references so ruff does not flag these as unused; they
# document the sizes we rely on at the module level.
_HEADER_SIZES = (HEADER_SIZE_32, HEADER_SIZE_64)

# Offsets are exposed as private constants in the module; mirror them here
# so the test does not reach into the implementation.
_H64_PHYSICAL_MEMORY_BLOCK = 0x088
_H64_DUMP_TYPE = 0xF98
_H32_PHYSICAL_MEMORY_BLOCK = 0x064
_H32_DUMP_TYPE = 0xF88


def _build_full_dump64(
    path: Path,
    runs: list[tuple[int, int]],  # list of (base_page, page_count)
    fill_byte: int | None = None,
) -> None:
    """Write a synthetic 64-bit FULL crash dump.

    Each page is filled with ``fill_byte`` when provided; otherwise each
    page is filled with a byte equal to ``page_index_within_file & 0xFF``.
    """
    header = bytearray(HEADER_SIZE_64)
    header[:8] = CRASHDUMP_MAGIC64
    header[8:12] = b"DUMP"  # ValidDump
    struct.pack_into("<I", header, 0x008, 15)  # MajorVersion
    struct.pack_into("<I", header, 0x00C, 1)  # MinorVersion
    struct.pack_into("<Q", header, 0x010, 0x1000)  # DirectoryTableBase
    struct.pack_into("<I", header, 0x030, 0x8664)  # MachineImageType (AMD64)
    struct.pack_into("<I", header, 0x034, 1)  # NumberProcessors
    struct.pack_into("<I", header, 0x038, 0x7F)  # BugCheckCode

    total_pages = sum(c for _, c in runs)
    struct.pack_into("<I", header, _H64_PHYSICAL_MEMORY_BLOCK, len(runs))
    struct.pack_into("<I", header, _H64_PHYSICAL_MEMORY_BLOCK + 4, total_pages)
    for i, (base, count) in enumerate(runs):
        off = _H64_PHYSICAL_MEMORY_BLOCK + 8 + i * 16
        struct.pack_into("<Q", header, off, base)
        struct.pack_into("<Q", header, off + 8, count)

    struct.pack_into("<I", header, _H64_DUMP_TYPE, DUMP_TYPE_FULL)

    body = bytearray()
    page_idx = 0
    for _, count in runs:
        for _ in range(count):
            if fill_byte is None:
                body.extend(bytes([page_idx & 0xFF]) * PAGE_SIZE)
            else:
                body.extend(bytes([fill_byte]) * PAGE_SIZE)
            page_idx += 1
    path.write_bytes(bytes(header) + bytes(body))


def _build_full_dump32(path: Path, runs: list[tuple[int, int]]) -> None:
    header = bytearray(HEADER_SIZE_32)
    header[:4] = CRASHDUMP_MAGIC32
    header[4:8] = b"DUMP"
    struct.pack_into("<I", header, 0x008, 15)
    struct.pack_into("<I", header, 0x010, 0x1000)  # DirectoryTableBase
    total_pages = sum(c for _, c in runs)
    struct.pack_into("<I", header, _H32_PHYSICAL_MEMORY_BLOCK, len(runs))
    struct.pack_into("<I", header, _H32_PHYSICAL_MEMORY_BLOCK + 4, total_pages)
    for i, (base, count) in enumerate(runs):
        off = _H32_PHYSICAL_MEMORY_BLOCK + 8 + i * 8
        struct.pack_into("<I", header, off, base)
        struct.pack_into("<I", header, off + 4, count)
    struct.pack_into("<I", header, _H32_DUMP_TYPE, DUMP_TYPE_FULL)

    body = bytearray()
    page_idx = 0
    for _, count in runs:
        for _ in range(count):
            body.extend(bytes([page_idx & 0xFF]) * PAGE_SIZE)
            page_idx += 1
    path.write_bytes(bytes(header) + bytes(body))


# ---------------------------------------------------------------------------
# Magic validation
# ---------------------------------------------------------------------------


class TestCrashDumpMagic:
    def test_rejects_bad_magic(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.dmp"
        bad.write_bytes(b"XXXX" + b"\x00" * 4096)
        with pytest.raises(FormatError):
            CrashDumpLayer(bad)

    def test_accepts_64bit_magic(self, tmp_path: Path) -> None:
        p = tmp_path / "x64.dmp"
        _build_full_dump64(p, runs=[(0, 1)])
        layer = CrashDumpLayer(p)
        try:
            assert layer.is_64bit is True
            assert layer.dump_type == DUMP_TYPE_FULL
        finally:
            layer.close()

    def test_accepts_32bit_magic(self, tmp_path: Path) -> None:
        p = tmp_path / "x86.dmp"
        _build_full_dump32(p, runs=[(0, 1)])
        layer = CrashDumpLayer(p)
        try:
            assert layer.is_64bit is False
        finally:
            layer.close()


# ---------------------------------------------------------------------------
# Read behaviour
# ---------------------------------------------------------------------------


class TestCrashDumpRead:
    def test_full_64_reads_each_page(self, tmp_path: Path) -> None:
        p = tmp_path / "full64.dmp"
        _build_full_dump64(p, runs=[(0, 4)])
        layer = CrashDumpLayer(p)
        try:
            for page_idx in range(4):
                data = layer.read(page_idx * PAGE_SIZE, PAGE_SIZE)
                assert len(data) == PAGE_SIZE
                assert data[0] == page_idx & 0xFF
                assert data[-1] == page_idx & 0xFF
        finally:
            layer.close()

    def test_full_32_reads_each_page(self, tmp_path: Path) -> None:
        p = tmp_path / "full32.dmp"
        _build_full_dump32(p, runs=[(0, 3)])
        layer = CrashDumpLayer(p)
        try:
            for page_idx in range(3):
                data = layer.read(page_idx * PAGE_SIZE, PAGE_SIZE)
                assert data[0] == page_idx & 0xFF
        finally:
            layer.close()

    def test_sparse_runs_with_gap(self, tmp_path: Path) -> None:
        # Pages 0..1 present, gap at PFN 2-3, pages 4..5 present.
        p = tmp_path / "sparse.dmp"
        _build_full_dump64(p, runs=[(0, 2), (4, 2)])
        layer = CrashDumpLayer(p)
        try:
            # PFN 0 -> file page 0 (value 0x00)
            assert layer.read(0, PAGE_SIZE)[0] == 0
            # PFN 1 -> file page 1 (value 0x01)
            assert layer.read(PAGE_SIZE, PAGE_SIZE)[0] == 1
            # PFN 4 -> file page 2 (value 0x02)
            assert layer.read(4 * PAGE_SIZE, PAGE_SIZE)[0] == 2
            # PFN 5 -> file page 3 (value 0x03)
            assert layer.read(5 * PAGE_SIZE, PAGE_SIZE)[0] == 3
            # PFN 2 / 3 are not present: no-pad -> empty.
            assert layer.read(2 * PAGE_SIZE, PAGE_SIZE) == b""
            # With pad -> zeros.
            assert layer.read(2 * PAGE_SIZE, PAGE_SIZE, pad=True) == b"\x00" * PAGE_SIZE
        finally:
            layer.close()

    def test_oob_read_with_pad(self, tmp_path: Path) -> None:
        p = tmp_path / "oob.dmp"
        _build_full_dump64(p, runs=[(0, 2)])
        layer = CrashDumpLayer(p)
        try:
            # Way past the end of the address space.
            data = layer.read(0x1000_0000, PAGE_SIZE, pad=True)
            assert data == b"\x00" * PAGE_SIZE
        finally:
            layer.close()

    def test_write_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "rw.dmp"
        _build_full_dump64(p, runs=[(0, 1)])
        layer = CrashDumpLayer(p)
        try:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"\x00")
        finally:
            layer.close()


class TestCrashDumpValidity:
    def test_is_valid_within_runs(self, tmp_path: Path) -> None:
        p = tmp_path / "v.dmp"
        _build_full_dump64(p, runs=[(0, 2), (4, 2)])
        layer = CrashDumpLayer(p)
        try:
            assert layer.is_valid(0) is True
            assert layer.is_valid(PAGE_SIZE) is True
            assert layer.is_valid(2 * PAGE_SIZE) is False  # gap
            assert layer.is_valid(5 * PAGE_SIZE) is True
        finally:
            layer.close()

    def test_address_bounds(self, tmp_path: Path) -> None:
        p = tmp_path / "b.dmp"
        _build_full_dump64(p, runs=[(0, 4)])
        layer = CrashDumpLayer(p)
        try:
            assert layer.minimum_address == 0
            assert layer.maximum_address == 4 * PAGE_SIZE - 1
        finally:
            layer.close()

    def test_metadata_records_os_and_arch(self, tmp_path: Path) -> None:
        p = tmp_path / "m.dmp"
        _build_full_dump64(p, runs=[(0, 1)])
        layer = CrashDumpLayer(p, name="blue-screen")
        try:
            md = layer.metadata
            assert md.name == "blue-screen"
            assert md.os == "windows"
            assert md.arch == "x64"
        finally:
            layer.close()


class TestCrashDumpLifecycle:
    def test_context_manager(self, tmp_path: Path) -> None:
        p = tmp_path / "ctx.dmp"
        _build_full_dump64(p, runs=[(0, 1)])
        with CrashDumpLayer(p) as layer:
            assert len(layer.read(0, PAGE_SIZE)) == PAGE_SIZE

    def test_del_cleanup(self, tmp_path: Path) -> None:
        p = tmp_path / "del.dmp"
        _build_full_dump64(p, runs=[(0, 1)])
        layer = CrashDumpLayer(p)
        layer.read(0, 8)
        del layer  # must not raise
