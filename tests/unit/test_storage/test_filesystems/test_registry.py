"""Tests for :func:`deepview.storage.filesystems.registry.register_all`."""
from __future__ import annotations

from typing import Any

import pytest

from deepview.storage.filesystems.registry import register_all


class _FakeManager:
    """Collects registered filesystem adapters without touching AnalysisContext."""

    def __init__(self) -> None:
        self._fs_adapters: dict[str, type] = {}

    def register_filesystem(self, name: str, cls: type) -> None:
        self._fs_adapters[name] = cls

    # Accept register_ftl / register_ecc calls for API parity.
    def register_ftl(self, name: str, cls: type) -> None:  # pragma: no cover
        pass

    def register_ecc(self, name: str, cls: type) -> None:  # pragma: no cover
        pass


class TestRegisterAll:
    def test_fat_always_registered(self) -> None:
        manager: Any = _FakeManager()
        register_all(manager)
        assert "fat" in manager._fs_adapters
        from deepview.storage.filesystems.fat_native import FATFilesystem

        assert manager._fs_adapters["fat"] is FATFilesystem

    def test_zfs_always_registered(self) -> None:
        manager: Any = _FakeManager()
        register_all(manager)
        assert "zfs" in manager._fs_adapters
        from deepview.storage.filesystems.zfs import ZFSFilesystem

        assert manager._fs_adapters["zfs"] is ZFSFilesystem

    def test_registration_is_idempotent(self) -> None:
        manager: Any = _FakeManager()
        register_all(manager)
        before = set(manager._fs_adapters)
        register_all(manager)
        after = set(manager._fs_adapters)
        assert before == after

    def test_optional_adapters_register_when_importable(self) -> None:
        """Every optional adapter that imports successfully must be registered."""
        manager: Any = _FakeManager()
        register_all(manager)
        checks = [
            ("pytsk3", "tsk"),
            ("pyfsapfs", "apfs"),
            ("pyfsntfs", "ntfs_native"),
            ("pyfsxfs", "xfs"),
            ("pyfsbtrfs", "btrfs"),
            ("pyfsf2fs", "f2fs"),
            ("pyfshfs", "hfs"),
            ("pyfsext", "ext"),
        ]
        for extra_mod, fs_name in checks:
            try:
                __import__(extra_mod)
            except ImportError:
                continue
            assert fs_name in manager._fs_adapters, (
                f"{fs_name} adapter expected when {extra_mod} is importable"
            )

    def test_missing_optional_deps_are_silent(self) -> None:
        """Calling register_all twice must not raise even if adapters fail."""
        manager: Any = _FakeManager()
        try:
            register_all(manager)
        except Exception as exc:  # pragma: no cover
            pytest.fail(f"register_all raised: {exc!r}")
