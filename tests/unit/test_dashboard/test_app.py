"""Lifecycle tests for DashboardApp driving panels with synthetic events."""
from __future__ import annotations


import pytest

from deepview.cli.dashboard.app import DashboardApp
from deepview.cli.dashboard.config import load_dashboard_config
from deepview.cli.dashboard.panels import EventTailPanel
from deepview.core.types import EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import TraceEventBus


def _event(**kwargs) -> MonitorEvent:
    process = kwargs.pop("process", None) or ProcessContext(
        pid=1, tid=1, ppid=0, uid=0, gid=0, comm="init"
    )
    source = kwargs.pop("source", None) or EventSource(
        platform="linux", backend="test", probe_name="t"
    )
    return MonitorEvent(process=process, source=source, **kwargs)


class TestDashboardApp:
    def test_builds_from_minimal_layout(self):
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        # Two panels expected: header + event_tail.
        assert len(app.panels) == 2

    def test_dispatch_trace_feeds_event_tail(self):
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        for _ in range(5):
            app.dispatch_trace(_event(syscall_name="read"))
        tail = [p for p in app.panels if isinstance(p, EventTailPanel)][0]
        assert len(tail._rows) == 5
        assert app._stats.events_received == 5

    def test_render_frame_returns_layout(self):
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        out = app.render_frame()
        # Rich Layout has a .name at least.
        assert out.name == "root"

    @pytest.mark.asyncio
    async def test_run_with_duration_zero_events(self):
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        bus = TraceEventBus()
        sub = bus.subscribe()
        try:
            stats = await app.run(trace_subscription=sub, duration=0.2)
        finally:
            bus.unsubscribe(sub)
        assert stats.events_received == 0
        assert stats.events_dropped == 0

    @pytest.mark.asyncio
    async def test_run_with_no_subscriptions_terminates(self):
        # With no event sources the loop has nothing to await; it must still
        # honour the duration deadline rather than busy-spin forever.
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        stats = await app.run(duration=0.2)
        assert stats.events_received == 0

    def test_render_frame_surfaces_subscription_drops(self):
        # Drops are tracked per-subscription; render_frame must report the real
        # total instead of a hardcoded zero.
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        bus = TraceEventBus()
        sub = bus.subscribe(queue_size=1)
        # Overflow the queue to force drops on the subscription.
        for _ in range(5):
            bus.publish_sync(_event(syscall_name="read"))
        assert sub.dropped_count == 4
        # Simulate the run wiring: the app drains this subscription.
        app._subscriptions = [sub]
        assert app._dropped_total() == 4

    @pytest.mark.asyncio
    async def test_run_folds_final_drops_into_stats(self):
        spec = load_dashboard_config(layout="minimal")
        app = DashboardApp(spec)
        bus = TraceEventBus()
        sub = bus.subscribe(queue_size=1)
        for _ in range(5):
            bus.publish_sync(_event(syscall_name="read"))
        assert sub.dropped_count == 4
        try:
            stats = await app.run(trace_subscription=sub, duration=0.2)
        finally:
            bus.unsubscribe(sub)
        # The queued event is consumed; the 4 drops persist in the summary.
        assert stats.events_received == 1
        assert stats.events_dropped == 4
