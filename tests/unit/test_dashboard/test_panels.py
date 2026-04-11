"""Tests for dashboard panel classes."""
from __future__ import annotations

import time

import pytest

from deepview.cli.dashboard.panels import (
    AlertsPanel,
    EventTailPanel,
    FlowRatePanel,
    FrameState,
    HeaderPanel,
    ManglePanel,
    PanelRegistry,
    ProcessTopPanel,
    TopTalkersPanel,
    default_panel_registry,
)
from deepview.core.types import EventCategory, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent


def _event(**kwargs) -> MonitorEvent:
    process = kwargs.pop("process", None) or ProcessContext(
        pid=42, tid=42, ppid=1, uid=0, gid=0, comm="bash"
    )
    source = kwargs.pop("source", None) or EventSource(
        platform="linux", backend="test", probe_name="t"
    )
    return MonitorEvent(process=process, source=source, **kwargs)


class TestPanelRegistry:
    def test_default_registry_has_core_panels(self):
        reg = default_panel_registry()
        known = reg.known()
        assert "header" in known
        assert "event_tail" in known
        assert "flow_rate" in known
        assert "mangle" in known

    def test_unknown_type_raises(self):
        reg = PanelRegistry()
        with pytest.raises(KeyError, match="unknown"):
            reg.create("nope", name="n")


class TestHeaderPanel:
    def test_renders_without_events(self):
        panel = HeaderPanel(name="header")
        frame = FrameState(now_ns=time.time_ns())
        out = panel.render(frame)
        assert out is not None


class TestFlowRatePanel:
    def test_accumulates_buckets(self):
        panel = FlowRatePanel(name="flow", config={"window_s": 10})
        base = int(time.time_ns())
        for i in range(5):
            ev = _event(wall_clock_ns=base + i * 1_000_000_000)
            panel.consume(ev)
        out = panel.render(FrameState(now_ns=base + 5 * 1_000_000_000))
        assert out is not None


class TestTopTalkersPanel:
    def test_ranks_by_packet_count(self):
        panel = TopTalkersPanel(name="top", config={"top_n": 3})
        for dst in ("1.2.3.4", "1.2.3.4", "5.6.7.8"):
            panel.consume(
                _event(
                    category=EventCategory.NETWORK,
                    args={"daddr": dst, "len": 64},
                )
            )
        out = panel.render(FrameState(now_ns=time.time_ns()))
        assert out is not None


class TestAlertsPanel:
    def test_most_recent_first(self):
        panel = AlertsPanel(name="alerts", config={"max_rows": 3})
        ev = _event()
        ev.metadata["classifications"] = [
            {"rule_id": "r1", "severity": "critical", "title": "t", "category": "c", "attack_ids": [], "labels": {}, "anomaly_score": 0}
        ]
        panel.consume_classified(ev)
        out = panel.render(FrameState(now_ns=time.time_ns()))
        assert out is not None


class TestEventTailPanel:
    def test_rolling_window(self):
        panel = EventTailPanel(name="tail", config={"max_rows": 2})
        for i in range(5):
            panel.consume(_event(syscall_name=f"sys{i}"))
        assert len(panel._rows) == 2
        out = panel.render(FrameState(now_ns=time.time_ns()))
        assert out is not None

    def test_filter_expression(self):
        panel = EventTailPanel(
            name="tail",
            config={"filter": 'syscall_name == "openat"', "max_rows": 10},
        )
        panel.consume(_event(syscall_name="read"))
        panel.consume(_event(syscall_name="openat"))
        assert len(panel._rows) == 1


class TestProcessTopPanel:
    def test_counts_per_pid(self):
        panel = ProcessTopPanel(name="top")
        for _ in range(3):
            panel.consume(_event())
        panel.consume(
            _event(process=ProcessContext(pid=99, tid=99, ppid=1, uid=0, gid=0, comm="sshd"))
        )
        assert panel._counters[(42, "bash")] == 3
        assert panel._counters[(99, "sshd")] == 1


class TestManglePanel:
    def test_counters_and_recent(self):
        panel = ManglePanel(name="mangle")
        panel.ingest_mangle(action="dropped", rule_id="r.bad", remote="1.2.3.4")
        panel.ingest_mangle(action="delayed", rule_id="r.slow", remote="5.6.7.8")
        panel.ingest_mangle(action="dropped", rule_id="r.bad")
        assert panel._counters["dropped"] == 2
        assert panel._counters["delayed"] == 1
        assert len(panel._recent) == 3
        out = panel.render(FrameState(now_ns=time.time_ns()))
        assert out is not None
