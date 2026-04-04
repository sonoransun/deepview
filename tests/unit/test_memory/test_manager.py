"""Tests for deepview.memory.manager — MemoryManager orchestration."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.exceptions import AnalysisError, FormatError
from deepview.core.types import DumpFormat
from deepview.memory.manager import MemoryManager


@pytest.fixture()
def manager(context: AnalysisContext) -> MemoryManager:
    """MemoryManager for testing (uses conftest context fixture)."""
    return MemoryManager(context)


class TestDetectFormat:
    """Tests for MemoryManager.detect_format."""

    def test_detect_format_raw(self, manager: MemoryManager, tmp_path: Path) -> None:
        """A file with arbitrary bytes should be detected as RAW."""
        raw_file = tmp_path / "random.bin"
        raw_file.write_bytes(os.urandom(256))
        assert manager.detect_format(raw_file) == DumpFormat.RAW

    def test_detect_format_lime(self, manager: MemoryManager, tmp_path: Path) -> None:
        """A file starting with LiME magic (0x4C694D45 LE) should be detected as LIME."""
        lime_file = tmp_path / "lime.bin"
        # LiME magic 0x4C694D45 in little-endian
        lime_file.write_bytes(b"\x45\x4d\x69\x4c" + b"\x00" * 252)
        assert manager.detect_format(lime_file) == DumpFormat.LIME

    def test_detect_format_elf(self, manager: MemoryManager, tmp_path: Path) -> None:
        """A file starting with ELF magic should be detected as ELF_CORE."""
        elf_file = tmp_path / "core.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 252)
        assert manager.detect_format(elf_file) == DumpFormat.ELF_CORE

    def test_detect_format_crashdump(self, manager: MemoryManager, tmp_path: Path) -> None:
        """A file starting with PAGE should be detected as CRASHDUMP."""
        crash_file = tmp_path / "crash.dmp"
        crash_file.write_bytes(b"PAGE" + b"\x00" * 252)
        assert manager.detect_format(crash_file) == DumpFormat.CRASHDUMP

    def test_detect_format_nonexistent_raises(self, manager: MemoryManager, tmp_path: Path) -> None:
        """FormatError is raised for a path that does not exist."""
        with pytest.raises(FormatError, match="File not found"):
            manager.detect_format(tmp_path / "nope.bin")

    def test_detect_format_directory_raises(self, manager: MemoryManager, tmp_path: Path) -> None:
        """FormatError is raised when the path is a directory."""
        with pytest.raises(FormatError, match="Not a file"):
            manager.detect_format(tmp_path)


class TestEnginesAndProviders:
    """Tests for engine/provider availability in test environment."""

    def test_get_engine_no_engines_raises(self, manager: MemoryManager) -> None:
        """AnalysisError when no analysis engines are available."""
        with pytest.raises(AnalysisError):
            manager.get_engine()

    def test_available_engines_empty(self, manager: MemoryManager) -> None:
        """In a test environment without vol3/memprocfs, available_engines is empty."""
        assert manager.available_engines == []

    def test_available_providers_list(self, manager: MemoryManager) -> None:
        """available_providers returns a list (possibly empty in test env)."""
        providers = manager.available_providers
        assert isinstance(providers, list)
