"""Tests for configuration."""
from deepview.core.config import DeepViewConfig

class TestDeepViewConfig:
    def test_default_config(self):
        config = DeepViewConfig()
        assert config.log_level == "info"
        assert config.output_format == "table"
        assert config.plugin_paths == []

    def test_memory_config_defaults(self):
        config = DeepViewConfig()
        assert config.memory.default_engine == "volatility"

    def test_acquisition_config_defaults(self):
        config = DeepViewConfig()
        assert config.acquisition.default_method == "auto"
        assert config.acquisition.compress is True

    def test_tracing_config_defaults(self):
        config = DeepViewConfig()
        assert config.tracing.default_duration == 30
        assert config.tracing.ring_buffer_pages == 64

    def test_load_nonexistent_returns_defaults(self):
        from pathlib import Path
        config = DeepViewConfig.load(Path("/nonexistent/path/config.toml"))
        assert config.log_level == "info"
