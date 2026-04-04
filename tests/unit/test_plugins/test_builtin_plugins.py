"""Tests for built-in plugins discovered via @register_plugin."""
from __future__ import annotations

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import PluginMetadata
from deepview.interfaces.plugin import PluginResult, Requirement

# Importing the builtin package triggers all @register_plugin decorators.
import deepview.plugins.builtin  # noqa: F401
from deepview.plugins.base import get_registered_plugins


@pytest.fixture()
def registered_plugins() -> dict[str, type]:
    """Return all registered plugins after builtin discovery."""
    return get_registered_plugins()


@pytest.fixture()
def test_context() -> AnalysisContext:
    return AnalysisContext.for_testing()


class TestBuiltinDiscovery:
    """Verify that all 9 built-in plugins are discovered."""

    def test_all_builtin_plugins_discovered(self, registered_plugins: dict[str, type]) -> None:
        """At least 9 builtin plugins should be registered."""
        assert len(registered_plugins) >= 9, (
            f"Expected at least 9 registered plugins, found {len(registered_plugins)}: "
            f"{list(registered_plugins.keys())}"
        )

    def test_expected_names_present(self, registered_plugins: dict[str, type]) -> None:
        """All expected plugin names should appear in the registry."""
        expected = {
            "pslist",
            "netstat",
            "malfind",
            "timeliner",
            "dkom_detect",
            "credentials",
            "pagetable_walk",
            "strings",
            "command_history",
        }
        assert expected.issubset(registered_plugins.keys())


class TestPluginMetadata:
    """Verify get_metadata() returns well-formed PluginMetadata."""

    def test_plugin_metadata(
        self, registered_plugins: dict[str, type], test_context: AnalysisContext
    ) -> None:
        for name, cls in registered_plugins.items():
            meta = cls.get_metadata()
            assert isinstance(meta, PluginMetadata), f"{name}: metadata is not PluginMetadata"
            assert meta.name, f"{name}: metadata.name is empty"
            assert meta.category, f"{name}: metadata.category is empty"
            assert meta.description, f"{name}: metadata.description is empty"


class TestPluginRequirements:
    """Verify get_requirements() returns a list of Requirement objects."""

    def test_plugin_requirements(self, registered_plugins: dict[str, type]) -> None:
        for name, cls in registered_plugins.items():
            reqs = cls.get_requirements()
            assert isinstance(reqs, list), f"{name}: requirements is not a list"
            for req in reqs:
                assert isinstance(req, Requirement), (
                    f"{name}: requirement {req!r} is not a Requirement"
                )


class TestPluginExecution:
    """Verify plugins can be instantiated and run without crashing."""

    def test_pslist_uses_correct_attributes(self, test_context: AnalysisContext) -> None:
        """ProcessListPlugin with empty config returns PluginResult, not AttributeError."""
        from deepview.plugins.builtin.pslist import ProcessListPlugin

        plugin = ProcessListPlugin(test_context, config={})
        result = plugin.run()
        assert isinstance(result, PluginResult)

    def test_plugins_with_missing_config(
        self, registered_plugins: dict[str, type], test_context: AnalysisContext
    ) -> None:
        """Every plugin should return PluginResult (not crash) when given empty config."""
        for name, cls in registered_plugins.items():
            plugin = cls(test_context, config={})
            result = plugin.run()
            assert isinstance(result, PluginResult), (
                f"{name}: run() did not return PluginResult, got {type(result)}"
            )
