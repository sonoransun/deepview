"""Tests for sequence/aggregate stateful classification rules."""
from __future__ import annotations

from deepview.classification.ruleset import Ruleset
from deepview.classification.sequences import StatefulMatcher
from deepview.core.types import EventCategory, ProcessContext
from deepview.tracing.events import MonitorEvent


# Base on a realistic epoch so wall_clock_ns is always truthy (a real event
# never carries a 0 timestamp; the matcher treats 0 as "unknown").
_BASE_S = 1_700_000_000


def _event(*, pid=10, sec=0, **kwargs) -> MonitorEvent:
    return MonitorEvent(
        wall_clock_ns=(_BASE_S + sec) * 1_000_000_000,
        process=ProcessContext(pid=pid, tid=pid, ppid=1, uid=0, gid=0, comm="p"),
        **kwargs,
    )


def _seq_rule() -> Ruleset:
    return Ruleset.from_mappings(
        [
            {
                "id": "seq.exec_connect",
                "title": "exec then connect",
                "severity": "critical",
                "attack_ids": ["T1204"],
                "sequence": [
                    {"match": 'syscall_name == "execve"'},
                    {"match": 'syscall_name == "connect"', "within_s": 30},
                ],
            }
        ]
    )


def _agg_rule() -> Ruleset:
    return Ruleset.from_mappings(
        [
            {
                "id": "agg.fanout",
                "title": "many destinations",
                "severity": "warning",
                "aggregate": {
                    "match": 'syscall_name == "connect"',
                    "field": "args.daddr",
                    "count": 3,
                    "within_s": 10,
                },
            }
        ]
    )


class TestSequence:
    def test_completes_in_order(self):
        m = StatefulMatcher(_seq_rule())
        assert m.feed(_event(sec=0, syscall_name="execve")) == []
        hits = m.feed(_event(sec=1, syscall_name="connect"))
        assert len(hits) == 1
        assert hits[0].rule_id == "seq.exec_connect"
        assert len(hits[0].matched_event_ids) == 2

    def test_out_of_order_does_not_fire(self):
        m = StatefulMatcher(_seq_rule())
        assert m.feed(_event(sec=0, syscall_name="connect")) == []
        assert m.feed(_event(sec=1, syscall_name="execve")) == []

    def test_window_expiry_resets_chain(self):
        m = StatefulMatcher(_seq_rule())
        m.feed(_event(sec=0, syscall_name="execve"))
        # connect arrives 31s later, past the 30s budget -> no hit.
        assert m.feed(_event(sec=31, syscall_name="connect")) == []

    def test_separate_pids_are_independent(self):
        m = StatefulMatcher(_seq_rule())
        m.feed(_event(pid=1, sec=0, syscall_name="execve"))
        # connect on a different PID should not complete pid 1's chain.
        assert m.feed(_event(pid=2, sec=1, syscall_name="connect")) == []


class TestAggregate:
    def test_distinct_field_threshold(self):
        m = StatefulMatcher(_agg_rule())
        for i, ip in enumerate(["1.1.1.1", "2.2.2.2"]):
            assert m.feed(
                _event(sec=i, category=EventCategory.NETWORK, syscall_name="connect", args={"daddr": ip})
            ) == []
        hits = m.feed(
            _event(sec=2, category=EventCategory.NETWORK, syscall_name="connect", args={"daddr": "3.3.3.3"})
        )
        assert len(hits) == 1
        assert hits[0].rule_id == "agg.fanout"

    def test_duplicate_values_do_not_count(self):
        m = StatefulMatcher(_agg_rule())
        for i in range(5):
            hits = m.feed(
                _event(sec=i, category=EventCategory.NETWORK, syscall_name="connect", args={"daddr": "1.1.1.1"})
            )
            assert hits == []  # only one distinct destination


class TestRulesetIntegration:
    def test_simple_classify_skips_stateful_rules(self):
        rs = Ruleset.from_mappings(
            [
                {"id": "simple", "match": 'syscall_name == "x"', "severity": "info"},
                {
                    "id": "stateful",
                    "severity": "warning",
                    "sequence": [{"match": 'syscall_name == "a"'}],
                },
            ]
        )
        # classify() must not crash on the match-less stateful rule.
        results = rs.classify(_event(syscall_name="x"))
        assert [r.rule_id for r in results] == ["simple"]
