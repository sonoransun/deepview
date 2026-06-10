"""Tests for the best-effort Sigma loader."""
from __future__ import annotations

import pytest

from deepview.classification.ruleset import Ruleset
from deepview.classification.sigma_loader import (
    SigmaUnsupported,
    load_sigma_dir,
    sigma_to_rule,
)
from deepview.core.types import ProcessContext
from deepview.tracing.events import MonitorEvent


def _event(*, process=None, **kwargs) -> MonitorEvent:
    return MonitorEvent(
        process=process or ProcessContext(pid=1, tid=1, ppid=1, uid=0, gid=0, comm="p"),
        **kwargs,
    )


SIMPLE_SIGMA = {
    "title": "Encoded PowerShell",
    "id": "abc-123",
    "level": "high",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": {
        "selection": {"CommandLine|contains": "-enc"},
        "condition": "selection",
    },
    "tags": ["attack.t1059.001"],
}


class TestConversion:
    def test_simple_rule_converts_and_matches(self):
        rule = sigma_to_rule(SIMPLE_SIGMA)
        assert rule.id == "abc-123"
        assert rule.severity == "critical"  # high -> critical
        assert rule.attack_ids == ["T1059.001"]
        assert rule.is_simple
        # CommandLine|contains maps to args.cmdline contains.
        ev = _event(args={"cmdline": "powershell -enc ZQBj"})
        assert rule.match is not None and rule.match.evaluate(ev)

    def test_list_value_becomes_or(self):
        rule = sigma_to_rule(
            {
                "title": "lolbins",
                "detection": {
                    "selection": {"Image|endswith": ["\\mshta.exe", "\\wscript.exe"]},
                    "condition": "selection",
                },
            }
        )
        ev = _event(process=ProcessContext(pid=1, tid=1, ppid=1, uid=0, gid=0, comm="x", exe_path="C:\\Windows\\mshta.exe"))
        assert rule.match is not None and rule.match.evaluate(ev)

    def test_and_condition(self):
        rule = sigma_to_rule(
            {
                "title": "two",
                "detection": {
                    "sel_a": {"CommandLine|contains": "-enc"},
                    "sel_b": {"CommandLine|contains": "bypass"},
                    "condition": "sel_a and sel_b",
                },
            }
        )
        assert rule.match is not None
        assert rule.match.evaluate(_event(args={"cmdline": "-enc x bypass"}))
        assert not rule.match.evaluate(_event(args={"cmdline": "-enc only"}))


class TestUnsupported:
    def test_not_condition_rejected(self):
        with pytest.raises(SigmaUnsupported):
            sigma_to_rule(
                {
                    "title": "n",
                    "detection": {"selection": {"a": "b"}, "condition": "selection and not filter"},
                }
            )

    def test_mixed_and_or_rejected(self):
        with pytest.raises(SigmaUnsupported):
            sigma_to_rule(
                {
                    "title": "m",
                    "detection": {
                        "a": {"x": "1"},
                        "b": {"y": "2"},
                        "c": {"z": "3"},
                        "condition": "a and b or c",
                    },
                }
            )

    def test_missing_detection_rejected(self):
        with pytest.raises(SigmaUnsupported):
            sigma_to_rule({"title": "x"})


class TestDirLoad:
    def test_load_dir_skips_unsupported(self, tmp_path):
        import yaml

        (tmp_path / "ok.yml").write_text(yaml.safe_dump(SIMPLE_SIGMA))
        (tmp_path / "bad.yml").write_text(
            yaml.safe_dump(
                {"title": "bad", "detection": {"sel": {"a": "b"}, "condition": "1 of them"}}
            )
        )
        ruleset = load_sigma_dir(tmp_path)
        assert len(ruleset) == 1  # bad one skipped

    def test_ruleset_classmethod(self, tmp_path):
        import yaml

        (tmp_path / "r.yml").write_text(yaml.safe_dump(SIMPLE_SIGMA))
        ruleset = Ruleset.load_sigma_dir(tmp_path)
        assert len(ruleset) == 1
