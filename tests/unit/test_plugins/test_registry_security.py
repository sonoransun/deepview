"""Security tests for plugin registry directory discovery."""
from __future__ import annotations

import pytest

from deepview.plugins.registry import PluginRegistry


class TestDirectoryTraversal:
    def test_symlink_plugin_dir_skipped(self, context, tmp_path):
        real_dir = tmp_path / "real_plugins"
        real_dir.mkdir()
        (real_dir / "plugin.py").write_text("x = 1\n")

        link_dir = tmp_path / "link_plugins"
        link_dir.symlink_to(real_dir)

        context.config.plugin_paths = [str(link_dir)]
        registry = PluginRegistry(context)
        # Should not crash; symlinked dir is skipped.
        registry._discover_directory()

    def test_nonexistent_plugin_dir_skipped(self, context, tmp_path):
        context.config.plugin_paths = [str(tmp_path / "nonexistent")]
        registry = PluginRegistry(context)
        registry._discover_directory()  # Should not crash

    def test_empty_plugin_dir_no_crash(self, context, tmp_path):
        empty_dir = tmp_path / "empty_plugins"
        empty_dir.mkdir()
        context.config.plugin_paths = [str(empty_dir)]
        registry = PluginRegistry(context)
        registry._discover_directory()  # Should not crash
