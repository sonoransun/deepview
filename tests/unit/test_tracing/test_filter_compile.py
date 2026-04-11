"""Tests for FilterExpr.compile() and parse_filter()."""
from __future__ import annotations

import pytest

from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import (
    FilterExpr,
    FilterPlan,
    FilterRule,
    FilterSyntaxError,
    parse_filter,
)
from deepview.core.types import EventCategory, EventSource, ProcessContext


def _event(**kwargs) -> MonitorEvent:
    ctx = kwargs.pop("process", None)
    if ctx is None:
        ctx = ProcessContext(pid=1, tid=1, ppid=0, uid=0, gid=0, comm="init")
    src = kwargs.pop("source", None) or EventSource(platform="linux", backend="test", probe_name="t")
    return MonitorEvent(process=ctx, source=src, **kwargs)


class TestCompile:
    def test_empty_filter_yields_empty_hints(self):
        plan = FilterExpr("and", []).compile()
        assert isinstance(plan, FilterPlan)
        assert plan.kernel_hints.is_empty()
        assert plan.remainder is not None

    def test_pid_eq_lifts_into_pids(self):
        expr = FilterExpr("and", [FilterRule("process.pid", "eq", 1234)])
        plan = expr.compile()
        assert plan.kernel_hints.pids == {1234}
        # Remainder still holds the rule so user-space evaluation
        # stays correct if the backend ignores the hints.
        assert plan.remainder is expr

    def test_pid_in_lifts_all_values(self):
        expr = FilterExpr("and", [FilterRule("process.pid", "in", [1, 2, 3])])
        plan = expr.compile()
        assert plan.kernel_hints.pids == {1, 2, 3}

    def test_comm_in_lifts_into_comms(self):
        expr = FilterExpr(
            "and",
            [FilterRule("process.comm", "in", ["sshd", "bash"])],
        )
        plan = expr.compile()
        assert plan.kernel_hints.comms == {"sshd", "bash"}

    def test_syscall_name_resolves_to_nr(self):
        # openat and openat2 are both in the x86_64 table.
        expr = FilterExpr(
            "and",
            [FilterRule("syscall_name", "in", ["openat", "openat2"])],
        )
        plan = expr.compile()
        assert 257 in plan.kernel_hints.syscall_nrs  # openat
        assert 437 in plan.kernel_hints.syscall_nrs  # openat2

    def test_or_root_is_not_lifted(self):
        # Top-level OR cannot be decomposed into an allowlist because
        # each disjunct is an independent match, so the whole thing
        # stays in the remainder and nothing is lifted.
        expr = FilterExpr(
            "or",
            [
                FilterRule("process.pid", "eq", 1),
                FilterRule("process.pid", "eq", 2),
            ],
        )
        plan = expr.compile()
        assert plan.kernel_hints.is_empty()

    def test_mixed_and_tree_partial_lift(self):
        expr = FilterExpr(
            "and",
            [
                FilterRule("process.pid", "eq", 42),
                FilterRule("args.path", "glob", "/etc/*"),  # not liftable
            ],
        )
        plan = expr.compile()
        assert plan.kernel_hints.pids == {42}
        # Non-liftable predicate is still in the tree for user-side eval.
        assert plan.remainder is expr


class TestParse:
    def test_pid_equality(self):
        expr = parse_filter("process.pid == 1234")
        assert isinstance(expr, FilterExpr)
        assert expr.op == "and"
        rule = expr.children[0]
        assert isinstance(rule, FilterRule)
        assert rule.field_path == "process.pid"
        assert rule.op == "eq"
        assert rule.value == 1234

    def test_list_literal(self):
        expr = parse_filter('syscall_name in ["openat", "openat2"]')
        rule = expr.children[0]
        assert isinstance(rule, FilterRule)
        assert rule.op == "in"
        assert rule.value == ["openat", "openat2"]

    def test_and_plus_glob(self):
        expr = parse_filter('process.comm == "bash" and args.path glob "/etc/*"')
        assert expr.op == "and"
        assert len(expr.children) == 2

    def test_not_operator(self):
        expr = parse_filter('not process.comm == "systemd"')
        # Top-level 'not' comes through as a NOT node directly.
        assert expr.op == "not"
        inner = expr.children[0]
        assert isinstance(inner, FilterRule)
        assert inner.field_path == "process.comm"

    def test_parens_force_grouping(self):
        expr = parse_filter('(process.pid == 1 or process.pid == 2) and process.uid == 0')
        assert expr.op == "and"
        first = expr.children[0]
        assert isinstance(first, FilterExpr)
        assert first.op == "or"

    def test_syntax_error(self):
        with pytest.raises(FilterSyntaxError):
            parse_filter("process.pid ==")

    def test_evaluation_roundtrip(self):
        expr = parse_filter('process.pid == 1 and process.comm == "init"')
        assert expr.evaluate(_event()) is True
        assert (
            expr.evaluate(
                _event(process=ProcessContext(pid=2, tid=2, ppid=0, uid=0, gid=0, comm="init"))
            )
            is False
        )


class TestCategoryNormalisation:
    def test_category_filter_uses_enum_value(self):
        # FilterExpr should compare the enum's .value so parse_filter
        # output matches events without the caller importing enums.
        expr = parse_filter('category == "process"')
        ev = _event(category=EventCategory.PROCESS)
        assert expr.evaluate(ev) is True
        ev2 = _event(category=EventCategory.NETWORK)
        assert expr.evaluate(ev2) is False
