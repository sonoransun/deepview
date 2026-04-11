"""Live tailing formatter for real-time trace event streams.

Unlike the other formatters in this package, the live renderer's primary
surface is the async :meth:`stream` method that consumes events from an
``EventSubscription`` and renders them in-place.  It still conforms to the
:class:`ResultRenderer` contract so that it can be looked up alongside the
table/JSON/CSV/timeline formatters.
"""
from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass, field
from typing import IO, Any

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from deepview.core.types import EventSeverity
from deepview.interfaces.plugin import PluginResult
from deepview.interfaces.renderer import ResultRenderer
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import EventSubscription


_SEVERITY_STYLE = {
    EventSeverity.INFO: "white",
    EventSeverity.WARNING: "yellow",
    EventSeverity.CRITICAL: "bold red",
}


@dataclass
class StreamStats:
    received: int = 0
    dropped: int = 0
    started_ns: int = 0
    last_ns: int = 0
    by_comm: dict[str, int] = field(default_factory=dict)
    by_syscall: dict[str, int] = field(default_factory=dict)


def _format_event_row(event: MonitorEvent) -> list[str]:
    pid = event.process.pid if event.process else 0
    comm = event.process.comm if event.process else "-"
    uid = event.process.uid if event.process else 0
    wall_s = event.wall_clock_ns / 1e9 if event.wall_clock_ns else 0.0
    ts = time.strftime("%H:%M:%S", time.localtime(wall_s)) if wall_s else "-"
    syscall = event.syscall_name or (str(event.syscall_nr) if event.syscall_nr >= 0 else "-")
    args_str = ", ".join(f"{k}={v}" for k, v in list(event.args.items())[:4])
    category = event.category.value if event.category else ""
    return [ts, str(pid), comm, str(uid), category, syscall, args_str]


def _row_style(event: MonitorEvent) -> str:
    return _SEVERITY_STYLE.get(event.severity, "white")


class LiveRenderer(ResultRenderer):
    """Render a live stream of :class:`MonitorEvent`s as a rolling table."""

    COLUMNS = ["Time", "PID", "Comm", "UID", "Cat", "Syscall", "Args"]

    def __init__(
        self,
        console: Console | None = None,
        *,
        max_rows: int = 25,
        refresh_per_second: float = 10.0,
    ) -> None:
        self._console = console or Console()
        self._max_rows = max_rows
        self._refresh = refresh_per_second
        self._rows: list[tuple[MonitorEvent, list[str]]] = []
        self.stats = StreamStats()

    def format_name(self) -> str:
        return "live"

    def render(self, result: PluginResult, output: IO | None = None) -> str:
        """Fallback render for a finalised ``PluginResult`` snapshot."""
        console = Console(file=output) if output else self._console
        table = Table(title="Live trace snapshot")
        for col in result.columns:
            table.add_column(col)
        for row in result.rows:
            table.add_row(*[str(row.get(col, "")) for col in result.columns])
        console.print(table)
        return ""

    def _build_table(self) -> Table:
        table = Table(expand=True, show_lines=False, pad_edge=False)
        for col in self.COLUMNS:
            table.add_column(col, overflow="fold")
        for event, cells in self._rows[-self._max_rows :]:
            table.add_row(*cells, style=_row_style(event))
        return table

    def _build_header(self, subscription: EventSubscription) -> Text:
        uptime = max(0.0, (self.stats.last_ns - self.stats.started_ns) / 1e9)
        rate = self.stats.received / uptime if uptime > 0 else 0.0
        top_comm = "-"
        if self.stats.by_comm:
            top_comm = max(self.stats.by_comm.items(), key=lambda kv: kv[1])[0]
        top_syscall = "-"
        if self.stats.by_syscall:
            top_syscall = max(self.stats.by_syscall.items(), key=lambda kv: kv[1])[0]
        dropped = subscription.dropped_count + self.stats.dropped
        return Text.assemble(
            ("deepview trace ", "bold cyan"),
            (f"events={self.stats.received} ", "white"),
            (f"rate={rate:.0f}/s ", "white"),
            (f"dropped={dropped} ", "yellow" if dropped else "dim"),
            (f"top_comm={top_comm} ", "green"),
            (f"top_syscall={top_syscall}", "magenta"),
        )

    def _ingest(self, event: MonitorEvent) -> None:
        self.stats.received += 1
        now_ns = event.wall_clock_ns or time.time_ns()
        if self.stats.started_ns == 0:
            self.stats.started_ns = now_ns
        self.stats.last_ns = now_ns
        if event.process:
            self.stats.by_comm[event.process.comm] = self.stats.by_comm.get(event.process.comm, 0) + 1
        name = event.syscall_name or (str(event.syscall_nr) if event.syscall_nr >= 0 else "")
        if name:
            self.stats.by_syscall[name] = self.stats.by_syscall.get(name, 0) + 1
        self._rows.append((event, _format_event_row(event)))
        if len(self._rows) > self._max_rows * 4:
            self._rows = self._rows[-self._max_rows * 2 :]

    async def stream(
        self,
        subscription: EventSubscription,
        *,
        duration: float | None = None,
        stop_event: asyncio.Event | None = None,
    ) -> StreamStats:
        """Consume events until *duration* elapses or *stop_event* is set.

        Renders a ``rich.live.Live`` panel at ~10 Hz. SIGINT flips the
        stop event so Ctrl-C terminates the stream cleanly. The method
        returns the final :class:`StreamStats` so the CLI can print a
        summary after tearing down the backend.
        """
        stop_event = stop_event or asyncio.Event()
        loop = asyncio.get_running_loop()
        # Install SIGINT handler so Ctrl-C exits cleanly.
        try:
            loop.add_signal_handler(signal.SIGINT, stop_event.set)
            loop.add_signal_handler(signal.SIGTERM, stop_event.set)
        except (NotImplementedError, RuntimeError):
            pass

        deadline: float | None = None
        if duration is not None:
            deadline = loop.time() + duration

        def _renderable() -> Any:
            from rich.console import Group
            return Group(self._build_header(subscription), self._build_table())

        with Live(
            _renderable(),
            console=self._console,
            refresh_per_second=self._refresh,
            transient=False,
        ) as live:
            while not stop_event.is_set():
                timeout = 0.2
                if deadline is not None:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    timeout = min(timeout, remaining)
                event = await subscription.get(timeout=timeout)
                if event is not None:
                    self._ingest(event)
                live.update(_renderable())

        try:
            loop.remove_signal_handler(signal.SIGINT)
            loop.remove_signal_handler(signal.SIGTERM)
        except (NotImplementedError, RuntimeError):
            pass
        return self.stats


def format_stats_summary(stats: StreamStats, sub: EventSubscription) -> str:
    uptime = max(0.0, (stats.last_ns - stats.started_ns) / 1e9) if stats.started_ns else 0.0
    rate = stats.received / uptime if uptime > 0 else 0.0
    return (
        f"received={stats.received} dropped={sub.dropped_count + stats.dropped} "
        f"uptime={uptime:.1f}s rate={rate:.1f}/s"
    )
