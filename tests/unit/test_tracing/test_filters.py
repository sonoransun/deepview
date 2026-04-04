"""Tests for the trace event filter DSL."""
from __future__ import annotations

import pytest

from deepview.core.types import EventCategory, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr, FilterRule


def _make_event(**kwargs) -> MonitorEvent:
    """Create a MonitorEvent with sensible defaults for testing."""
    return MonitorEvent(**kwargs)


def _make_event_with_process(pid: int = 100, comm: str = "test") -> MonitorEvent:
    """Create a MonitorEvent with a ProcessContext attached."""
    proc = ProcessContext(pid=pid, tid=pid, ppid=1, uid=0, gid=0, comm=comm)
    return MonitorEvent(process=proc)


class TestFilterRuleBasicOps:
    """Test individual filter rule operators."""

    def test_filter_rule_eq(self):
        expr = FilterExpr("and", [FilterRule("syscall_name", "eq", "open")])
        event = _make_event(syscall_name="open")
        assert expr.evaluate(event) is True

        event_no = _make_event(syscall_name="read")
        assert expr.evaluate(event_no) is False

    def test_filter_rule_ne(self):
        expr = FilterExpr("and", [FilterRule("syscall_name", "ne", "open")])

        assert expr.evaluate(_make_event(syscall_name="read")) is True
        assert expr.evaluate(_make_event(syscall_name="open")) is False

    def test_filter_rule_gt_lt(self):
        expr_gt = FilterExpr("and", [FilterRule("syscall_nr", "gt", 10)])
        expr_lt = FilterExpr("and", [FilterRule("syscall_nr", "lt", 10)])

        event_high = _make_event(syscall_nr=20)
        event_low = _make_event(syscall_nr=5)

        assert expr_gt.evaluate(event_high) is True
        assert expr_gt.evaluate(event_low) is False
        assert expr_lt.evaluate(event_low) is True
        assert expr_lt.evaluate(event_high) is False


class TestFilterRuleStringOps:
    """Test string-oriented filter operators."""

    def test_filter_contains(self):
        expr = FilterExpr("and", [FilterRule("syscall_name", "contains", "ope")])

        assert expr.evaluate(_make_event(syscall_name="open")) is True
        assert expr.evaluate(_make_event(syscall_name="close")) is False

    def test_filter_glob(self):
        expr = FilterExpr("and", [FilterRule("syscall_name", "glob", "read*")])

        assert expr.evaluate(_make_event(syscall_name="readlink")) is True
        assert expr.evaluate(_make_event(syscall_name="write")) is False

    def test_filter_regex(self):
        expr = FilterExpr("and", [FilterRule("syscall_name", "regex", r"^(open|close)$")])

        assert expr.evaluate(_make_event(syscall_name="open")) is True
        assert expr.evaluate(_make_event(syscall_name="close")) is True
        assert expr.evaluate(_make_event(syscall_name="openat")) is False


class TestFilterExprCompound:
    """Test compound (and/or/not) filter expressions."""

    def test_filter_and_compound(self):
        expr = FilterExpr("and", [
            FilterRule("syscall_name", "eq", "open"),
            FilterRule("syscall_nr", "gt", 0),
        ])

        # Both match
        assert expr.evaluate(_make_event(syscall_name="open", syscall_nr=2)) is True
        # Only one matches
        assert expr.evaluate(_make_event(syscall_name="open", syscall_nr=-1)) is False
        assert expr.evaluate(_make_event(syscall_name="read", syscall_nr=2)) is False

    def test_filter_or_compound(self):
        expr = FilterExpr("or", [
            FilterRule("syscall_name", "eq", "open"),
            FilterRule("syscall_name", "eq", "close"),
        ])

        assert expr.evaluate(_make_event(syscall_name="open")) is True
        assert expr.evaluate(_make_event(syscall_name="close")) is True
        assert expr.evaluate(_make_event(syscall_name="read")) is False

    def test_filter_not(self):
        expr = FilterExpr("not", [FilterRule("syscall_name", "eq", "open")])

        assert expr.evaluate(_make_event(syscall_name="read")) is True
        assert expr.evaluate(_make_event(syscall_name="open")) is False


class TestFilterExprConvenience:
    """Test convenience class methods."""

    def test_pid_filter_convenience(self):
        expr = FilterExpr.pid_filter(123)
        event_match = _make_event_with_process(pid=123)
        event_no = _make_event_with_process(pid=456)

        assert expr.evaluate(event_match) is True
        assert expr.evaluate(event_no) is False

    def test_category_filter_convenience(self):
        expr = FilterExpr.category_filter(EventCategory.SYSCALL_RAW)
        event_match = _make_event(category=EventCategory.SYSCALL_RAW)
        event_no = _make_event(category=EventCategory.NETWORK)

        assert expr.evaluate(event_match) is True
        assert expr.evaluate(event_no) is False


class TestResolveNestedField:
    """Test dot-path field resolution."""

    def test_resolve_nested_field(self):
        expr = FilterExpr("and", [FilterRule("process.pid", "eq", 42)])
        event = _make_event_with_process(pid=42)

        assert expr.evaluate(event) is True

    def test_resolve_nested_field_dict(self):
        """Dot-path should also resolve through dict keys (args dict)."""
        expr = FilterExpr("and", [FilterRule("args.path", "eq", "/etc/passwd")])
        event = _make_event(args={"path": "/etc/passwd"})

        assert expr.evaluate(event) is True

    def test_resolve_missing_field_returns_false(self):
        expr = FilterExpr("and", [FilterRule("nonexistent.field", "eq", "value")])
        event = _make_event()

        assert expr.evaluate(event) is False
