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

    def render_frame(self) -> object:
        frame = FrameState(
            now_ns=time.time_ns(),
            started_ns=self._stats.started_ns,
            events_received=self._stats.events_received,
            events_dropped=0,
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
        return self._stats

    def request_stop(self) -> None:
        if self._stopped is not None:
            self._stopped.set()
