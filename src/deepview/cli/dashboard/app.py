"""The async dashboard application that drives the Rich Live loop."""
from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass

from rich.console import Console
from rich.live import Live

from deepview.cli.dashboard.config import LayoutSpec
from deepview.cli.dashboard.layout import DashboardLayout
from deepview.cli.dashboard.panels import (
    FrameState,
    Panel,
    PanelRegistry,
    default_panel_registry,
)
from deepview.core.logging import get_logger
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import EventSubscription

log = get_logger("cli.dashboard.app")


@dataclass
class DashboardStats:
    started_ns: int = 0
    last_ns: int = 0
    events_received: int = 0
    events_dropped: int = 0


class DashboardApp:
    """Owns the panel list + Rich layout + the async frame loop."""

    def __init__(
        self,
        spec: LayoutSpec,
        *,
        console: Console | None = None,
        registry: PanelRegistry | None = None,
    ) -> None:
        self._spec = spec
        self._console = console or Console()
        self._registry = registry or default_panel_registry()
        self._panels: list[Panel] = [
            self._registry.create(p.type, name=p.name, config=p.config)
            for p in spec.panels
        ]
        self._layout = DashboardLayout(spec, self._panels)
        self._stats = DashboardStats()
        self._stopped: asyncio.Event | None = None
        self._subscriptions: list[EventSubscription] = []

    @property
    def panels(self) -> list[Panel]:
        return list(self._panels)

    @property
    def layout(self) -> DashboardLayout:
        return self._layout

    def dispatch_trace(self, event: MonitorEvent) -> None:
        self._stats.events_received += 1
        now_ns = event.wall_clock_ns or time.time_ns()
        if self._stats.started_ns == 0:
            self._stats.started_ns = now_ns
        self._stats.last_ns = now_ns
        for panel in self._panels:
            if panel.subscribes_trace:
                try:
                    panel.consume(event)
                except Exception as e:  # noqa: BLE001
                    log.warning("panel_consume_error", name=panel.name, error=str(e))

    def dispatch_classified(self, event: MonitorEvent) -> None:
        for panel in self._panels:
            if panel.subscribes_classified:
                try:
                    panel.consume_classified(event)
                except Exception as e:  # noqa: BLE001
                    log.warning("panel_classify_error", name=panel.name, error=str(e))

    def tick(self, now_ns: int | None = None) -> None:
        t = now_ns or time.time_ns()
        for panel in self._panels:
            try:
                panel.tick(t)
            except Exception as e:  # noqa: BLE001
                log.warning("panel_tick_error", name=panel.name, error=str(e))

    def _dropped_total(self) -> int:
        """Sum the drop counters of every subscription this run is draining,
        plus any drops already folded into the stats. Subscriptions silently
        discard events on queue overflow, so the dashboard must surface this
        rather than report a hardcoded zero."""
        return self._stats.events_dropped + sum(
            sub.dropped_count for sub in self._subscriptions
        )

    def render_frame(self) -> object:
        frame = FrameState(
            now_ns=time.time_ns(),
            started_ns=self._stats.started_ns,
            events_received=self._stats.events_received,
            events_dropped=self._dropped_total(),
        )
        return self._layout.render(frame)

    async def run(
        self,
        *,
        trace_subscription: EventSubscription | None = None,
        classified_subscription: EventSubscription | None = None,
        duration: float | None = None,
        tick_every_s: float = 0.5,
    ) -> DashboardStats:
        """Drive the Rich Live loop.

        The app consumes at most one event per pump iteration from each
        of its subscriptions; this is the same pattern the existing
        :class:`LiveRenderer` uses.
        """
        self._stopped = asyncio.Event()
        # Drops are accumulated live from the subscriptions during the run;
        # reset the folded counter so a second run() does not double-count.
        self._stats.events_dropped = 0
        self._subscriptions = [
            sub
            for sub in (trace_subscription, classified_subscription)
            if sub is not None
        ]
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, self._stopped.set)
            loop.add_signal_handler(signal.SIGTERM, self._stopped.set)
        except (NotImplementedError, RuntimeError):
            pass

        deadline: float | None = None
        if duration is not None:
            deadline = loop.time() + duration

        refresh_per_second = max(1.0, self._spec.refresh_hz)
        next_tick = loop.time()

        with Live(
            self.render_frame(),
            console=self._console,
            refresh_per_second=refresh_per_second,
            transient=False,
        ) as live:
            while not self._stopped.is_set():
                if deadline is not None and loop.time() >= deadline:
                    break
                # Event pumps: non-blocking drain.
                if trace_subscription is not None:
                    event = await trace_subscription.get(timeout=0.05)
                    if event is not None:
                        self.dispatch_trace(event)
                if classified_subscription is not None:
                    event = await classified_subscription.get(timeout=0.05)
                    if event is not None:
                        self.dispatch_classified(event)
                if trace_subscription is None and classified_subscription is None:
                    # No event sources: the loop has nothing to await, so yield
                    # to the event loop instead of busy-spinning a CPU core.
                    await asyncio.sleep(0.05)
                # Periodic tick + frame.
                now = loop.time()
                if now >= next_tick:
                    self.tick()
                    next_tick = now + tick_every_s
                live.update(self.render_frame())

        try:
            loop.remove_signal_handler(signal.SIGINT)
            loop.remove_signal_handler(signal.SIGTERM)
        except (NotImplementedError, RuntimeError):
            pass
        # Fold the final per-subscription drop counts into the stats so the
        # returned summary stays accurate after the subscriptions are gone.
        self._stats.events_dropped = self._dropped_total()
        self._subscriptions = []
        return self._stats

    def request_stop(self) -> None:
        if self._stopped is not None:
            self._stopped.set()
