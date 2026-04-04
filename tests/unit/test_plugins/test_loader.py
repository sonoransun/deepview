"""Tests for deepview.plugins.loader — module loading utilities."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.exceptions import PluginLoadError
from deepview.plugins.loader import load_module_by_name, load_module_from_path


class TestLoadModuleFromPath:
    """Tests for load_module_from_path."""

    def test_load_nonexistent_path(self, tmp_path: Path) -> None:
        """Returns None when the file does not exist."""
        result = load_module_from_path(tmp_path / "does_not_exist.py")
        assert result is None

    def test_load_non_py_file(self, tmp_path: Path) -> None:
        """Returns None for a non-.py file."""
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("hello")
        result = load_module_from_path(txt_file)
        assert result is None

    def test_load_valid_module(self, tmp_path: Path) -> None:
        """Loads a valid .py file and returns the module object."""
        plugin_file = tmp_path / "sample_plugin.py"
        plugin_file.write_text(
            "class SamplePlugin:\n"
            "    name = 'sample'\n"
        )
        module = load_module_from_path(plugin_file)
        assert module is not None
        assert hasattr(module, "SamplePlugin")
        assert module.SamplePlugin.name == "sample"

    def test_load_invalid_module_raises(self, tmp_path: Path) -> None:
        """Raises PluginLoadError when the file has a syntax error."""
        bad_file = tmp_path / "bad_plugin.py"
        bad_file.write_text("def broken(\n")
        with pytest.raises(PluginLoadError):
            load_module_from_path(bad_file)


class TestLoadModuleByName:
    """Tests for load_module_by_name."""

    def test_load_module_by_name_success(self) -> None:
        """Successfully imports a stdlib module by dotted name."""
        module = load_module_by_name("json")
        assert module is not None
        assert hasattr(module, "dumps")

    def test_load_module_by_name_failure(self) -> None:
        """Raises PluginLoadError for a non-existent module."""
        with pytest.raises(PluginLoadError):
            load_module_by_name("nonexistent.module.xyz")
