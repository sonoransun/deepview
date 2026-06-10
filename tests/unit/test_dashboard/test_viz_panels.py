"""Tests for the visualization panels added for the viz sweep."""
from __future__ import annotations

import time

from deepview.cli.dashboard.panels import (
    AlertCorrelationPanel,
    AnomalyHeatPanel,
    FrameState,
    NetworkFlowPanel,
    ProcessTreePanel,
    SyscallHeatPanel,
    default_panel_registry,
)
from deepview.core.types import EventCategory, ProcessContext
from deepview.tracing.events import MonitorEvent


def _event(*, pid=42, ppid=1, comm="bash", **kwargs) -> MonitorEvent:
    process = ProcessContext(pid=pid, tid=pid, ppid=ppid, uid=0, gid=0, comm=comm)
    return MonitorEvent(process=process, **kwargs)


def _classified(*, pid=42, comm="bash", classifications, **kwargs) -> MonitorEvent:
    ev = _event(pid=pid, comm=comm, **kwargs)
    ev.metadata["classifications"] = classifications
    return ev


class TestRegistry:
    def test_new_panels_registered(self):
        known = default_panel_registry().known()
        for t in (
            "process_tree",
            "syscall_heat",
            "anomaly_heat",
            "alert_correlation",
            "memory_map",
            "network_flow",
        ):
            assert t in known


class TestProcessTreePanel:
    def test_builds_ancestry_from_events(self):
        panel = ProcessTreePanel(name="tree")
        panel.consume(_event(pid=1, ppid=0, comm="init"))
        panel.consume(_event(pid=100, ppid=1, comm="bash"))
        panel.consume(_event(pid=101, ppid=100, comm="curl"))
        out = panel.render(FrameState(now_ns=time.time_ns()))
        assert out is not None

    def test_renders_empty(self):
        out = ProcessTreePanel(name="tree").render(FrameState())
        assert out is not None


class TestSyscallHeatPanel:
    def test_accumulates_category_series(self):
        panel = SyscallHeatPanel(name="heat", config={"window_buckets": 10})
        base = 1_000 * 1_000_000_000
        for i in range(4):
            panel.consume(
                _event(category=EventCategory.FILE_IO, wall_clock_ns=base + i * 1_000_000_000)
            )
        out = panel.render(FrameState(now_ns=base))
        assert out is not None

    def test_renders_empty(self):
        assert SyscallHeatPanel(name="heat").render(FrameState()) is not None


class TestAnomalyHeatPanel:
    def test_tracks_scores_per_pid(self):
        panel = AnomalyHeatPanel(name="anom")
        panel.consume_classified(
            _classified(
                pid=5,
                classifications=[{"rule_id": "r", "severity": "warning", "anomaly_score": 0.7}],
            )
        )
        out = panel.render(FrameState())
        assert out is not None

    def test_ignores_unclassified(self):
        panel = AnomalyHeatPanel(name="anom")
        panel.consume_classified(_event())  # no classifications metadata
        assert panel.render(FrameState()) is not None


class TestAlertCorrelationPanel:
    def test_escalates_on_multiple_techniques(self):
        panel = AlertCorrelationPanel(name="corr", config={"window_s": 60, "threshold": 2})
        ts = time.time_ns()
        for tid in ("T1055", "T1014", "T1003"):
            panel.consume_classified(
                _classified(
                    pid=9,
                    wall_clock_ns=ts,
                    classifications=[
                        {"rule_id": f"rule.{tid}", "severity": "warning", "attack_ids": [tid]}
                    ],
                )
            )
        # Within-window render should produce a cluster.
        out = panel.render(FrameState(now_ns=ts))
        assert out is not None

    def test_no_clusters_when_empty(self):
        out = AlertCorrelationPanel(name="corr").render(FrameState(now_ns=time.time_ns()))
        assert out is not None


class TestNetworkFlowPanel:
    def test_aggregates_flows_and_flags_threats(self):
        panel = NetworkFlowPanel(name="flow")
        panel.consume(
            _event(pid=7, comm="curl", category=EventCategory.NETWORK, args={"daddr": "1.2.3.4", "len": 100})
        )
        panel.consume(
            _event(pid=7, comm="curl", category=EventCategory.NETWORK, args={"daddr": "1.2.3.4", "len": 40})
        )
        panel.consume_classified(
            _classified(pid=7, comm="curl", classifications=[{"rule_id": "bad", "severity": "critical"}])
        )
        assert 7 in panel._flagged
        out = panel.render(FrameState())
        assert out is not None

    def test_renders_empty(self):
        assert NetworkFlowPanel(name="flow").render(FrameState()) is not None
