"""Security tests for YARA rule management."""
from __future__ import annotations

import pytest

from deepview.scanning.rules.manager import RuleManager, _validate_rule_name


class TestRuleNameValidation:
    def test_valid_name(self):
        _validate_rule_name("malware")  # Should not raise
        _validate_rule_name("my-rules")
        _validate_rule_name("creds_2024")

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="Invalid rule name"):
            _validate_rule_name("../../etc/passwd")

    def test_slash_rejected(self):
        with pytest.raises(ValueError, match="Invalid rule name"):
            _validate_rule_name("path/to/rule")

    def test_dot_dot_rejected(self):
        with pytest.raises(ValueError, match="Invalid rule name"):
            _validate_rule_name("..")

    def test_empty_name_rejected(self):
        with pytest.raises(ValueError, match="Invalid rule name"):
            _validate_rule_name("")

    def test_space_rejected(self):
        with pytest.raises(ValueError, match="Invalid rule name"):
            _validate_rule_name("rule name")

    def test_special_chars_rejected(self):
        with pytest.raises(ValueError, match="Invalid rule name"):
            _validate_rule_name("rule;rm -rf")


class TestRulePathContainment:
    def test_get_rule_path_normal(self, config, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "malware.yar").write_text("rule test { condition: true }")
        config.memory.yara_rules_dir = rules_dir
        mgr = RuleManager(config)
        result = mgr.get_rule_path("malware")
        assert result is not None
        assert result.name == "malware.yar"

    def test_get_rule_path_nonexistent(self, config, tmp_path):
        config.memory.yara_rules_dir = tmp_path / "rules"
        mgr = RuleManager(config)
        result = mgr.get_rule_path("nonexistent")
        assert result is None
