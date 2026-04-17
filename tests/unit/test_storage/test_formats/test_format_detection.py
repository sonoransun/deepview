"""Tests for ``MemoryManager.detect_format`` recognising the esoteric formats."""
from __future__ import annotations

from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.types import DumpFormat
from deepview.memory.manager import MemoryManager


def _manager() -> MemoryManager:
    return MemoryManager(AnalysisContext.for_testing())


class TestDetectFormatEsoteric:
    def test_minidump_mdmp(self, tmp_path: Path) -> None:
        path = tmp_path / "crash.dmp"
        path.write_bytes(b"MDMP" + b"\x00" * 60)
        assert _manager().detect_format(path) == DumpFormat.MINIDUMP_FULL

    def test_hiberfil_hibr(self, tmp_path: Path) -> None:
        path = tmp_path / "hiberfil.sys"
        path.write_bytes(b"hibr" + b"\x00" * 60)
        assert _manager().detect_format(path) == DumpFormat.HIBERFIL

    def test_hiberfil_wake(self, tmp_path: Path) -> None:
        path = tmp_path / "hiberfil.sys"
        path.write_bytes(b"wake" + b"\x00" * 60)
        assert _manager().detect_format(path) == DumpFormat.HIBERFIL

    def test_virtualbox_ssm_magic(self, tmp_path: Path) -> None:
        path = tmp_path / "vm.sav"
        path.write_bytes(b"SSM" + b"\x00" * 61)
        assert _manager().detect_format(path) == DumpFormat.VIRTUALBOX_SAV

    def test_vmware_vmem_by_extension(self, tmp_path: Path) -> None:
        path = tmp_path / "guest.vmem"
        # No magic; the dispatcher must use the extension.
        path.write_bytes(b"\x00" * 64)
        assert _manager().detect_format(path) == DumpFormat.VMWARE_VMEM

    def test_hyperv_vmrs_by_extension(self, tmp_path: Path) -> None:
        path = tmp_path / "state.vmrs"
        path.write_bytes(b"\x00" * 64)
        assert _manager().detect_format(path) == DumpFormat.HYPERV_VMRS

    def test_default_raw_for_unknown(self, tmp_path: Path) -> None:
        path = tmp_path / "blob.bin"
        path.write_bytes(b"\xAB" * 128)
        assert _manager().detect_format(path) == DumpFormat.RAW
