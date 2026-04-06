"""Security tests for configuration loading."""
from __future__ import annotations

import pytest

from deepview.core.config import DeepViewConfig
from deepview.core.exceptions import ConfigError


class TestConfigFileValidation:
    def test_symlink_config_rejected(self, tmp_path):
        real = tmp_path / "real_config.toml"
        real.write_text('[general]\nlog_level = "info"\n')
        link = tmp_path / "link_config.toml"
        link.symlink_to(real)
        with pytest.raises(ConfigError, match="symlink"):
            DeepViewConfig.load(link)

    def test_large_config_rejected(self, tmp_path):
        huge = tmp_path / "huge_config.toml"
        huge.write_bytes(b"x" * (11 * 1024 * 1024))  # 11 MB
        with pytest.raises(ConfigError, match="too large"):
            DeepViewConfig.load(huge)

    def test_invalid_toml_raises(self, tmp_path):
        bad = tmp_path / "bad_config.toml"
        bad.write_text("this is not valid [[[toml")
        with pytest.raises(ConfigError, match="Invalid TOML"):
            DeepViewConfig.load(bad)

    def test_valid_config_loads(self, tmp_path):
        good = tmp_path / "good_config.toml"
        good.write_text('[memory]\ndefault_engine = "volatility"\n')
        config = DeepViewConfig.load(good)
        assert config.memory.default_engine == "volatility"

    def test_nonexistent_config_returns_defaults(self, tmp_path):
        config = DeepViewConfig.load(tmp_path / "nonexistent.toml")
        assert config.log_level == "info"

    def test_empty_config_loads(self, tmp_path):
        empty = tmp_path / "empty_config.toml"
        empty.write_text("")
        config = DeepViewConfig.load(empty)
        assert config.log_level == "info"
