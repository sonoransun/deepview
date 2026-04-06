"""Security tests for plugin loader."""
from __future__ import annotations

import os
import platform
import pytest

from deepview.core.exceptions import PluginLoadError
from deepview.plugins.loader import load_module_from_path


class TestSymlinkRejection:
    def test_symlink_plugin_rejected(self, tmp_path):
        real = tmp_path / "real_plugin.py"
        real.write_text("x = 1\n")
        link = tmp_path / "symlink_plugin.py"
        link.symlink_to(real)
        with pytest.raises(PluginLoadError, match="symlink"):
            load_module_from_path(link)


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix permissions")
class TestPermissionChecks:
    def test_world_writable_plugin_rejected(self, tmp_path):
        plugin = tmp_path / "writable_plugin.py"
        plugin.write_text("x = 1\n")
        plugin.chmod(0o777)
        with pytest.raises(PluginLoadError, match="world-writable"):
            load_module_from_path(plugin)


class TestBasicValidation:
    def test_nonexistent_file_returns_none(self, tmp_path):
        result = load_module_from_path(tmp_path / "nonexistent.py")
        assert result is None

    def test_non_py_file_returns_none(self, tmp_path):
        f = tmp_path / "notpython.txt"
        f.write_text("hello")
        result = load_module_from_path(f)
        assert result is None

    def test_syntax_error_raises_plugin_load_error(self, tmp_path):
        f = tmp_path / "bad_syntax.py"
        f.write_text("def broken(\n")
        with pytest.raises(PluginLoadError):
            load_module_from_path(f)

    def test_valid_plugin_loads(self, tmp_path):
        f = tmp_path / "good_plugin.py"
        f.write_text("PLUGIN_VALUE = 42\n")
        module = load_module_from_path(f)
        assert module is not None
        assert module.PLUGIN_VALUE == 42
