"""Tests for the classification Ruleset loader and matcher."""
from __future__ import annotations

import textwrap

import pytest

from deepview.classification import ClassificationRule, Ruleset, RuleLoadError
from deepview.core.types import EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent


def _event(**kwargs) -> MonitorEvent:
    process = kwargs.pop("process", None) or ProcessContext(
        pid=42, tid=42, ppid=1, uid=0, gid=0, comm="test"
    )
    source = kwargs.pop("source", None) or EventSource(
        platform="linux", backend="test", probe_name="t"
    )
    return MonitorEvent(process=process, source=source, **kwargs)


class TestRuleFromMapping:
    def test_minimal_rule(self):
        rule = ClassificationRule.from_mapping(
            {"id": "r1", "match": "process.pid == 1"}
        )
        assert rule.id == "r1"
        assert rule.severity == "warning"  # default
        assert rule.match.evaluate(_event(process=ProcessContext(pid=1, tid=1, ppid=0, uid=0, gid=0, comm="init")))

    def test_missing_id(self):
        with pytest.raises(RuleLoadError, match="id"):
            ClassificationRule.from_mapping({"match": "process.pid == 1"})

    def test_missing_match(self):
        with pytest.raises(RuleLoadError, match="match"):
            ClassificationRule.from_mapping({"id": "r1"})

    def test_invalid_severity(self):
        with pytest.raises(RuleLoadError, match="severity"):
            ClassificationRule.from_mapping(
                {"id": "r1", "match": "process.pid == 1", "severity": "oops"}
            )

    def test_bad_match_expression(self):
        with pytest.raises(RuleLoadError, match="match expression"):
            ClassificationRule.from_mapping({"id": "r1", "match": "process.pid =="})


class TestRulesetYaml:
    def test_load_list_yaml(self, tmp_path):
        path = tmp_path / "rules.yaml"
        path.write_text(
            textwrap.dedent(
                """
                - id: exec_tmp
                  title: Exec from /tmp
                  severity: critical
                  match: 'syscall_name == "execve" and args.filename glob "/tmp/*"'
                  labels:
                    tactic: execution
                """
            )
        )
        rs = Ruleset.load_yaml(path)
        assert len(rs) == 1
        rule = next(iter(rs))
        assert rule.id == "exec_tmp"
        assert rule.severity == "critical"
        assert rule.labels == {"tactic": "execution"}

    def test_load_rules_key_yaml(self, tmp_path):
        path = tmp_path / "rules.yaml"
        path.write_text(
            textwrap.dedent(
                """
                rules:
                  - id: a
                    match: process.pid == 1
                  - id: b
                    match: process.uid == 0
                """
            )
        )
        rs = Ruleset.load_yaml(path)
        assert len(rs) == 2

    def test_builtin_ruleset_loads(self):
        rs = Ruleset.load_builtin()
        # Starter pack should have at least a handful of rules.
        assert len(rs) >= 5
        ids = {r.id for r in rs}
        assert any(i.startswith("linux.") for i in ids)


class TestClassify:
    def test_single_match(self):
        rs = Ruleset.from_mappings(
            [
                {
                    "id": "r1",
                    "match": 'syscall_name == "execve" and args.filename glob "/tmp/*"',
                    "severity": "critical",
                }
            ]
        )
        ev = _event(syscall_name="execve", args={"filename": "/tmp/x"})
        matches = rs.classify(ev)
        assert len(matches) == 1
        assert matches[0].rule_id == "r1"
        assert matches[0].severity == "critical"

    def test_no_match(self):
        rs = Ruleset.from_mappings(
            [{"id": "r1", "match": 'process.comm == "sshd"'}]
        )
        matches = rs.classify(_event(process=ProcessContext(pid=1, tid=1, ppid=0, uid=0, gid=0, comm="init")))
        assert matches == []
