"""Panel base class and the concrete panels shipped with Deep View.

Every panel is a small state machine:

* :meth:`consume` is called (from the dashboard app's main loop) for
  each :class:`MonitorEvent` the panel is subscribed to.
* :meth:`tick` is called periodically regardless of event traffic —
  useful for panels that poll ``/proc`` or a netlink socket instead
  of (or in addition to) event-driven updates.
* :meth:`render` returns a Rich renderable that the layout drops
  into its assigned region.

Panels are registered by string name in :class:`PanelRegistry` so the
YAML layout config can instantiate them without importing each one.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from typing import ClassVar

from rich.console import Group, RenderableType
from rich.panel import Panel as RichPanel
from rich.table import Table
from rich.text import Text

from deepview.core.types import EventCategory, EventSeverity
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr, FilterSyntaxError, parse_filter


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


@dataclass
class FrameState:
    """Small bag of data all panels share per render frame."""

    now_ns: int = 0
    started_ns: int = 0
    events_received: int = 0
    events_dropped: int = 0


class Panel(ABC):
    """Abstract dashboard panel.

    Subclasses set a class-level ``type_name`` and implement
    :meth:`render`. They may optionally override :meth:`consume` and
    :meth:`tick`.
    """

    type_name: ClassVar[str] = ""
    subscribes_trace: ClassVar[bool] = False
    subscribes_classified: ClassVar[bool] = False

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        self.name = name
        self.config = config or {}
        self._filter: FilterExpr | None = None
        expr_text = self.config.get("filter")
        if expr_text:
            try:
                self._filter = parse_filter(str(expr_text))
            except FilterSyntaxError as e:
                raise ValueError(
                    f"panel {name!r}: invalid filter expression: {e}"
                ) from e

    @abstractmethod
    def render(self, frame: FrameState) -> RenderableType:
        """Return the panel's current renderable."""

    def consume(self, event: MonitorEvent) -> None:
        """Ingest a trace event. Override when ``subscribes_trace`` is True."""

    def consume_classified(self, event: MonitorEvent) -> None:
        """Ingest a classified trace event (already labelled)."""

    def tick(self, now_ns: int) -> None:
        """Called periodically regardless of event traffic."""

    def _passes_filter(self, event: MonitorEvent) -> bool:
        if self._filter is None:
            return True
        try:
            return self._filter.evaluate(event)
        except Exception:  # noqa: BLE001 - filter bugs shouldn't kill the panel
            return False

    def _framed(self, body: RenderableType, *, title: str | None = None) -> RenderableType:
        return RichPanel(body, title=title or self.name, border_style="cyan")


# ---------------------------------------------------------------------------
# Header + status panels
# ---------------------------------------------------------------------------


class HeaderPanel(Panel):
    type_name = "header"

    def render(self, frame: FrameState) -> RenderableType:
        import platform as _pl

        uptime = max(0.0, (frame.now_ns - frame.started_ns) / 1e9) if frame.started_ns else 0.0
        rate = frame.events_received / uptime if uptime > 0 else 0.0
        return RichPanel(
            Text.assemble(
                ("deepview dashboard  ", "bold cyan"),
                (f"host={_pl.node()} ", "white"),
                (f"kernel={_pl.release()} ", "white"),
                (f"events={frame.events_received} ", "green"),
                (f"rate={rate:.0f}/s ", "green"),
                (f"dropped={frame.events_dropped} ", "yellow" if frame.events_dropped else "dim"),
                (f"uptime={uptime:.0f}s", "white"),
            ),
            border_style="cyan",
        )


# ---------------------------------------------------------------------------
# Flow rate sparkline (ASCII only, no rich.sparkline dep on older rich)
# ---------------------------------------------------------------------------


class FlowRatePanel(Panel):
    type_name = "flow_rate"
    subscribes_trace = True

    _SPARK = "▁▂▃▄▅▆▇█"

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._window_s = float(self.config.get("window_s", 60.0))
        self._buckets: deque[int] = deque(maxlen=max(20, int(self._window_s)))
        self._last_bucket_ts = 0
        self._pkts_in_current = 0
        self._metric = str(self.config.get("metric", "events_per_second"))

    def consume(self, event: MonitorEvent) -> None:
        if not self._passes_filter(event):
            return
        now = int((event.wall_clock_ns or time.time_ns()) / 1e9)
        if self._last_bucket_ts == 0:
            self._last_bucket_ts = now
        while self._last_bucket_ts < now:
            self._buckets.append(self._pkts_in_current)
            self._pkts_in_current = 0
            self._last_bucket_ts += 1
        self._pkts_in_current += 1

    def render(self, frame: FrameState) -> RenderableType:
        values = list(self._buckets)
        if not values:
            body = Text("(no samples yet)", style="dim")
        else:
            mx = max(values) or 1
            spark = "".join(
                self._SPARK[min(len(self._SPARK) - 1, int(v / mx * (len(self._SPARK) - 1)))]
                for v in values
            )
            peak = max(values)
            avg = sum(values) / len(values)
            body = Text.assemble(
                (spark + "\n", "cyan"),
                (f"peak={peak}/s  avg={avg:.1f}/s  window={int(self._window_s)}s", "white"),
            )
        return self._framed(body, title=f"{self.name} ({self._metric})")


# ---------------------------------------------------------------------------
# Top talkers — per-remote endpoint counters
# ---------------------------------------------------------------------------


class TopTalkersPanel(Panel):
    type_name = "top_talkers"
    subscribes_trace = True

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._top_n = int(self.config.get("top_n", 10))
        self._counters: dict[tuple[str, str], tuple[int, int]] = {}

    def consume(self, event: MonitorEvent) -> None:
        if not self._passes_filter(event):
            return
        if event.category not in (EventCategory.NETWORK, EventCategory.SYSCALL_RAW):
            return
        remote = None
        for key in ("daddr", "remote", "dest", "dst"):
            if key in event.args and event.args[key]:
                remote = str(event.args[key])
                break
        if remote is None:
            return
        comm = event.process.comm if event.process else "-"
        key = (remote, comm)
        pkts, bytes_ = self._counters.get(key, (0, 0))
        pkts += 1
        bytes_ += int(event.args.get("len", 0) or 0)
        self._counters[key] = (pkts, bytes_)

    def render(self, frame: FrameState) -> RenderableType:
        table = Table(expand=True, show_edge=False, pad_edge=False)
        table.add_column("Remote")
        table.add_column("Comm")
        table.add_column("Pkts", justify="right")
        table.add_column("Bytes", justify="right")
        ranked = sorted(
            self._counters.items(),
            key=lambda kv: (kv[1][0], kv[1][1]),
            reverse=True,
        )[: self._top_n]
        if not ranked:
            table.add_row("(no traffic)", "", "", "", style="dim")
        for (remote, comm), (pkts, bytes_) in ranked:
            table.add_row(remote[:24], comm[:16], str(pkts), str(bytes_))
        return self._framed(table)


# ---------------------------------------------------------------------------
# Connections — /proc/net polled every N ticks
# ---------------------------------------------------------------------------


class ConnectionsPanel(Panel):
    type_name = "connections"

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._refresh_ns = int(float(self.config.get("refresh_s", 2.0)) * 1e9)
        self._next_refresh_ns = 0
        self._rows: list[dict[str, str]] = []
        self._state_filter = self.config.get("state")
        self._max_rows = int(self.config.get("max_rows", 15))

    def tick(self, now_ns: int) -> None:
        if now_ns < self._next_refresh_ns:
            return
        self._next_refresh_ns = now_ns + self._refresh_ns
        try:
            from deepview.tracing.linux import procfs

            enriched = procfs.enrich_sockets_with_pids(procfs.iter_sockets())
        except Exception:  # noqa: BLE001
            self._rows = []
            return
        rows: list[dict[str, str]] = []
        for s in enriched:
            if self._state_filter and s.state != self._state_filter:
                continue
            rows.append(
                {
                    "proto": s.proto,
                    "local": f"{s.local_ip}:{s.local_port}",
                    "remote": f"{s.remote_ip}:{s.remote_port}",
                    "state": s.state,
                    "pid": str(s.pid) if s.pid else "",
                    "comm": s.comm,
                }
            )
        self._rows = rows[: self._max_rows]

    def render(self, frame: FrameState) -> RenderableType:
        table = Table(expand=True, show_edge=False)
        for col in ("Proto", "Local", "Remote", "State", "PID", "Comm"):
            table.add_column(col, overflow="fold")
        if not self._rows:
            table.add_row("(none)", "", "", "", "", "", style="dim")
        for r in self._rows:
            table.add_row(r["proto"], r["local"], r["remote"], r["state"], r["pid"], r["comm"])
        return self._framed(table)


# ---------------------------------------------------------------------------
# Alerts — last N classifier hits
# ---------------------------------------------------------------------------


class AlertsPanel(Panel):
    type_name = "alerts"
    subscribes_classified = True

    _SEVERITY_STYLE = {"info": "white", "warning": "yellow", "critical": "bold red"}

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._max_rows = int(self.config.get("max_rows", 10))
        self._alerts: deque[tuple[int, str, str, str]] = deque(maxlen=self._max_rows)

    def consume_classified(self, event: MonitorEvent) -> None:
        classifications = event.metadata.get("classifications", [])
        if not classifications:
            return
        worst = max(
            classifications,
            key=lambda c: {"info": 0, "warning": 1, "critical": 2}.get(c.get("severity", "info"), 0),
        )
        pid = event.process.pid if event.process else 0
        comm = event.process.comm if event.process else ""
        ts = event.wall_clock_ns or time.time_ns()
        self._alerts.appendleft((
            ts,
            worst.get("severity", "info"),
            worst.get("rule_id", ""),
            f"{comm}({pid})",
        ))

    def render(self, frame: FrameState) -> RenderableType:
        table = Table(expand=True, show_edge=False)
        table.add_column("Time")
        table.add_column("Sev")
        table.add_column("Rule")
        table.add_column("Proc")
        if not self._alerts:
            table.add_row("—", "", "(no classifier hits)", "", style="dim")
        for ts, sev, rule, proc in self._alerts:
            style = self._SEVERITY_STYLE.get(sev, "white")
            table.add_row(
                time.strftime("%H:%M:%S", time.localtime(ts / 1e9)),
                sev,
                rule,
                proc,
                style=style,
            )
        return self._framed(table)


# ---------------------------------------------------------------------------
# Event tail — rolling table of the most recent events
# ---------------------------------------------------------------------------


class EventTailPanel(Panel):
    type_name = "event_tail"
    subscribes_trace = True

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._max_rows = int(self.config.get("max_rows", 15))
        self._rows: deque[tuple[int, MonitorEvent]] = deque(maxlen=self._max_rows)

    def consume(self, event: MonitorEvent) -> None:
        if not self._passes_filter(event):
            return
        self._rows.append((event.wall_clock_ns or time.time_ns(), event))

    def render(self, frame: FrameState) -> RenderableType:
        table = Table(expand=True, show_edge=False)
        for col in ("Time", "PID", "Comm", "Cat", "Syscall", "Args"):
            table.add_column(col, overflow="fold")
        if not self._rows:
            table.add_row("—", "", "", "", "", "(no events)", style="dim")
        for ts, ev in list(self._rows)[-self._max_rows:]:
            ts_str = time.strftime("%H:%M:%S", time.localtime(ts / 1e9))
            pid = str(ev.process.pid) if ev.process else "0"
            comm = ev.process.comm if ev.process else ""
            cat = ev.category.value if ev.category else ""
            call = ev.syscall_name or (str(ev.syscall_nr) if ev.syscall_nr >= 0 else "")
            args = ", ".join(f"{k}={v}" for k, v in list(ev.args.items())[:3])
            style = "bold red" if ev.severity == EventSeverity.CRITICAL else None
            table.add_row(ts_str, pid, comm, cat, call, args, style=style)
        return self._framed(table)


# ---------------------------------------------------------------------------
# Process top by event rate
# ---------------------------------------------------------------------------


class ProcessTopPanel(Panel):
    type_name = "process_top"
    subscribes_trace = True

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._top_n = int(self.config.get("top_n", 10))
        self._counters: dict[tuple[int, str], int] = {}

    def consume(self, event: MonitorEvent) -> None:
        if not self._passes_filter(event) or event.process is None:
            return
        key = (event.process.pid, event.process.comm)
        self._counters[key] = self._counters.get(key, 0) + 1

    def render(self, frame: FrameState) -> RenderableType:
        table = Table(expand=True, show_edge=False)
        table.add_column("PID", justify="right")
        table.add_column("Comm")
        table.add_column("Events", justify="right")
        ranked = sorted(self._counters.items(), key=lambda kv: kv[1], reverse=True)[: self._top_n]
        if not ranked:
            table.add_row("—", "(no events)", "0", style="dim")
        for (pid, comm), count in ranked:
            table.add_row(str(pid), comm[:20], str(count))
        return self._framed(table)


# ---------------------------------------------------------------------------
# Mangle panel — subscribes to NetworkPacketMangledEvent on the core bus
# ---------------------------------------------------------------------------


class ManglePanel(Panel):
    type_name = "mangle"

    def __init__(self, *, name: str, config: dict | None = None) -> None:
        super().__init__(name=name, config=config)
        self._max_rows = int(self.config.get("max_rows", 10))
        self._counters: dict[str, int] = {
            "accepted": 0,
            "dropped": 0,
            "delayed": 0,
            "rewritten": 0,
            "corrupted": 0,
            "marked": 0,
            "errors": 0,
            "observed": 0,
        }
        self._by_rule: dict[str, int] = {}
        self._recent: deque[tuple[int, str, str, str]] = deque(maxlen=self._max_rows)

    def ingest_mangle(
        self,
        *,
        action: str,
        rule_id: str,
        remote: str = "",
        ts_ns: int | None = None,
    ) -> None:
        ts = ts_ns or time.time_ns()
        self._counters[action] = self._counters.get(action, 0) + 1
        self._by_rule[rule_id] = self._by_rule.get(rule_id, 0) + 1
        self._recent.appendleft((ts, action, rule_id, remote))

    def render(self, frame: FrameState) -> RenderableType:
        stats = Table.grid(expand=True, padding=(0, 1))
        stats.add_column()
        stats.add_column(justify="right")
        for key in ("accepted", "dropped", "delayed", "rewritten", "corrupted", "marked", "observed", "errors"):
            stats.add_row(key, str(self._counters.get(key, 0)))

        rule_table = Table(expand=True, show_edge=False, title="Top rules")
        rule_table.add_column("Rule")
        rule_table.add_column("Hits", justify="right")
        ranked = sorted(self._by_rule.items(), key=lambda kv: kv[1], reverse=True)[:5]
        if not ranked:
            rule_table.add_row("(none)", "0", style="dim")
        for rid, hits in ranked:
            rule_table.add_row(rid[:24], str(hits))

        recent = Table(expand=True, show_edge=False, title="Recent actions")
        recent.add_column("Time")
        recent.add_column("Action")
        recent.add_column("Rule")
        recent.add_column("Remote")
        if not self._recent:
            recent.add_row("—", "", "", "", style="dim")
        for ts, action, rule, remote in list(self._recent):
            recent.add_row(
                time.strftime("%H:%M:%S", time.localtime(ts / 1e9)),
                action,
                rule[:20],
                remote[:24],
            )

        return self._framed(Group(stats, rule_table, recent))


# ---------------------------------------------------------------------------
# Panel registry
# ---------------------------------------------------------------------------


class PanelRegistry:
    """Maps ``type`` strings in YAML to panel classes."""

    def __init__(self) -> None:
        self._types: dict[str, type[Panel]] = {}

    def register(self, cls: type[Panel]) -> None:
        if not cls.type_name:
            raise ValueError(f"panel class {cls.__name__} must set type_name")
        self._types[cls.type_name] = cls

    def create(self, type_name: str, *, name: str, config: dict | None = None) -> Panel:
        if type_name not in self._types:
            raise KeyError(f"unknown panel type: {type_name!r}")
        return self._types[type_name](name=name, config=config)

    def known(self) -> list[str]:
        return sorted(self._types.keys())


def default_panel_registry() -> PanelRegistry:
    registry = PanelRegistry()
    for cls in (
        HeaderPanel,
        FlowRatePanel,
        TopTalkersPanel,
        ConnectionsPanel,
        AlertsPanel,
        EventTailPanel,
        ProcessTopPanel,
        ManglePanel,
    ):
        registry.register(cls)
    return registry
