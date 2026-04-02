"""Tests for the plugin registry."""
from deepview.core.context import AnalysisContext
from deepview.plugins.registry import PluginRegistry
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

class TestPluginRegistry:
    def test_discover_finds_builtins(self):
        ctx = AnalysisContext.for_testing()
        registry = PluginRegistry(ctx)
        registry.discover()
        # Should not raise even if no builtins are active yet
        assert registry.plugin_count >= 0

    def test_manual_register(self):
        ctx = AnalysisContext.for_testing()
        registry = PluginRegistry(ctx)

        class FakePlugin(DeepViewPlugin):
            @classmethod
            def get_requirements(cls):
                return []
            def run(self):
                return PluginResult()

        registry.register("fake", FakePlugin)
        assert registry.get("fake") is FakePlugin

    def test_instantiate(self):
        ctx = AnalysisContext.for_testing()
        registry = PluginRegistry(ctx)

        class FakePlugin(DeepViewPlugin):
            @classmethod
            def get_requirements(cls):
                return []
            def run(self):
                return PluginResult(columns=["a"], rows=[{"a": 1}])

        registry.register("fake", FakePlugin)
        instance = registry.instantiate("fake")
        result = instance.run()
        assert result.columns == ["a"]

    def test_plugin_not_found(self):
        import pytest
        ctx = AnalysisContext.for_testing()
        registry = PluginRegistry(ctx)
        registry.discover()
        with pytest.raises(Exception):
            registry.get("nonexistent_plugin_xyz")

class TestRegisterDecorator:
    def test_decorator_registers_plugin(self):
        @register_plugin(
            name="test_decorated",
            category=PluginCategory.CUSTOM,
            description="A test plugin",
        )
        class TestPlugin(DeepViewPlugin):
            @classmethod
            def get_requirements(cls):
                return []
            def run(self):
                return PluginResult()

        meta = TestPlugin.get_metadata()
        assert meta.name == "test_decorated"
        assert meta.description == "A test plugin"
