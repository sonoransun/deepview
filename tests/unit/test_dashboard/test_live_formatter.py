"""Tests for the live trace formatter row builder edge cases."""
from __future__ import annotations

from deepview.cli.formatters.live import _format_event_row
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent


def _event(**kwargs) -> MonitorEvent:
    process = kwargs.pop("process", None) or ProcessContext(
        pid=42, tid=42, ppid=1, uid=0, gid=0, comm="bash"
    )
    source = kwargs.pop("source", None) or EventSource(
        platform="linux", backend="test", probe_name="t"
    )
    return MonitorEvent(process=process, source=source, **kwargs)


class TestFormatEventRow:
    def test_no_args_renders_empty_args_cell(self):
        row = _format_event_row(_event(syscall_name="read"))
        assert row[-1] == ""

    def test_four_args_render_fully_without_truncation_marker(self):
        args = {"a": 1, "b": 2, "c": 3, "d": 4}
        row = _format_event_row(_event(syscall_name="read", args=args))
        assert row[-1] == "a=1, b=2, c=3, d=4"
        assert "more" not in row[-1]

    def test_excess_args_are_truncated_with_count_marker(self):
        args = {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}
        row = _format_event_row(_event(syscall_name="read", args=args))
        # First four shown, plus an honest indicator of how many were dropped.
        assert row[-1].startswith("a=1, b=2, c=3, d=4")
        assert row[-1].endswith("+2 more")

    def test_missing_process_uses_placeholders(self):
        # MonitorEvent allows a None process; the row must not crash.
        event = MonitorEvent(process=None, source=None, syscall_name="read")
        row = _format_event_row(event)
        # [ts, pid, comm, uid, cat, syscall, args]
        assert row[1] == "0"
        assert row[2] == "-"
        assert row[3] == "0"

    def test_syscall_falls_back_to_number_then_dash(self):
        # Named syscall wins.
        assert _format_event_row(_event(syscall_name="openat"))[5] == "openat"
        # No name, valid number -> the number.
        assert _format_event_row(_event(syscall_nr=257))[5] == "257"
        # No name and sentinel number -> dash.
        assert _format_event_row(_event(syscall_nr=-1))[5] == "-"

    def test_category_rendered_from_enum_value(self):
        row = _format_event_row(_event(category=EventCategory.NETWORK))
        assert row[4] == "network"

    def test_row_has_expected_column_count(self):
        row = _format_event_row(_event(severity=EventSeverity.WARNING))
        assert len(row) == 7
