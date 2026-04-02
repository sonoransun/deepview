"""Tests for the analysis context."""
from deepview.core.context import AnalysisContext, LayerRegistry, ArtifactStore

class TestLayerRegistry:
    def test_register_and_get(self):
        reg = LayerRegistry()
        reg.register("test", object())
        assert reg.has("test")
        assert reg.get("test") is not None

    def test_list_layers(self):
        reg = LayerRegistry()
        reg.register("a", object())
        reg.register("b", object())
        assert sorted(reg.list_layers()) == ["a", "b"]

    def test_missing_layer(self):
        reg = LayerRegistry()
        import pytest
        with pytest.raises(KeyError):
            reg.get("missing")

class TestArtifactStore:
    def test_add_and_get(self):
        store = ArtifactStore()
        store.add("processes", {"pid": 1, "name": "init"})
        store.add("processes", {"pid": 2, "name": "bash"})
        assert len(store.get("processes")) == 2

    def test_categories(self):
        store = ArtifactStore()
        store.add("processes", {"pid": 1})
        store.add("network", {"conn": "tcp"})
        assert sorted(store.categories()) == ["network", "processes"]

    def test_empty_category(self):
        store = ArtifactStore()
        assert store.get("nonexistent") == []

class TestAnalysisContext:
    def test_for_testing(self):
        ctx = AnalysisContext.for_testing()
        assert ctx.session_id
        assert ctx.config is not None
        assert ctx.layers is not None
        assert ctx.events is not None

    def test_session_id_unique(self):
        ctx1 = AnalysisContext.for_testing()
        ctx2 = AnalysisContext.for_testing()
        assert ctx1.session_id != ctx2.session_id

    def test_lazy_plugin_registry(self):
        ctx = AnalysisContext.for_testing()
        # Accessing .plugins should lazily create the registry
        registry = ctx.plugins
        assert registry is not None
        # Second access returns same instance
        assert ctx.plugins is registry
