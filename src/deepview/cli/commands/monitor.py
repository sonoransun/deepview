"""Real-time monitor CLI group.

``deepview monitor`` owns the long-running, always-on forensic
dashboards. It differs from ``deepview trace`` in that it layers
classification, pre-event context capture, and auto-inspection on
top of the raw trace stream — the commands here are the ones you
leave running on a suspect host.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console

from deepview.cli.formatters.live import LiveRenderer, format_stats_summary
from deepview.classification import EventClassifier, Ruleset
from deepview.core.context import AnalysisContext
from deepview.core.events import EventClassifiedEvent
from deepview.core.exceptions import MonitorError
from deepview.core.types import EventCategory, ProbeType
from deepview.inspect.process import ProcessInspector
from deepview.replay.circular import CircularEventBuffer
from deepview.replay.store import SessionStore
from deepview.tracing.filters import FilterExpr, FilterRule, FilterSyntaxError, parse_filter
from deepview.tracing.manager import TraceManager
from deepview.tracing.providers.base import ProbeSpec


@click.group()
def monitor() -> None:
    """Real-time forensic monitoring on the local host."""


@monitor.command("tail")
@click.option("--duration", type=int, default=30, show_default=True)
@click.option("--pid", type=int, default=None)
@click.option("--filter", "filter_expr", type=str, default=None)
@click.pass_context
def monitor_tail(ctx, duration, pid, filter_expr):
    """Live tail of trace events (no persistence)."""
    asyncio.run(_tail(ctx, duration=duration, pid=pid, filter_text=filter_expr))


async def _tail(ctx, *, duration: int, pid: int | None, filter_text: str | None) -> None:
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    children: list = []
    if pid is not None:
        children.append(FilterRule("process.pid", "eq", int(pid)))
    if filter_text:
        try:
            children.append(parse_filter(filter_text))
        except FilterSyntaxError as e:
            raise click.BadParameter(f"--filter: {e}") from e
    filt = FilterExpr("and", children) if children else None

    manager = TraceManager.from_context(context)
    probes = [ProbeSpec(category=EventCategory.SYSCALL_RAW, probe_type=ProbeType.TRACEPOINT)]
    try:
        await manager.start(probes, filter_expr=filt)
    except MonitorError as e:
        console.print(f"[red]{e}[/red]")
        return
    renderer = LiveRenderer(console=console)
    subscription = manager.bus.subscribe()
    try:
        stats = await renderer.stream(subscription, duration=float(duration))
    finally:
        manager.bus.unsubscribe(subscription)
        await manager.stop()
    console.print(f"[dim]{format_stats_summary(stats, subscription)}[/dim]")


@monitor.command("alert")
@click.option("--ruleset", type=click.Path(exists=True, dir_okay=False), default=None, help="YAML ruleset path (defaults to the built-in Linux baseline)")
@click.option("--output", type=click.Path(dir_okay=False), default=None, help="Persist matching events + snapshots to a session db")
@click.option("--duration", type=int, default=60, show_default=True)
@click.option("--pid", type=int, default=None)
@click.option("--filter", "filter_expr", type=str, default=None)
@click.option("--auto-inspect/--no-auto-inspect", default=True, show_default=True)
@click.pass_context
def monitor_alert(ctx, ruleset, output, duration, pid, filter_expr, auto_inspect):
    """Live classification: run rules against the trace stream and react."""
    asyncio.run(
        _alert(
            ctx,
            ruleset_path=ruleset,
            output=Path(output) if output else None,
            duration=duration,
            pid=pid,
            filter_text=filter_expr,
            auto_inspect=auto_inspect,
        )
    )


async def _alert(
    ctx,
    *,
    ruleset_path: str | None,
    output: Path | None,
    duration: int,
    pid: int | None,
    filter_text: str | None,
    auto_inspect: bool,
) -> None:
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    rs = (
        Ruleset.load_yaml(ruleset_path)
        if ruleset_path is not None
        else Ruleset.load_builtin()
    )
    if not rs:
        console.print("[yellow]warning: no rules loaded[/yellow]")

    children: list = []
    if pid is not None:
        children.append(FilterRule("process.pid", "eq", int(pid)))
    if filter_text:
        try:
            children.append(parse_filter(filter_text))
        except FilterSyntaxError as e:
            raise click.BadParameter(f"--filter: {e}") from e
    filt = FilterExpr("and", children) if children else None

    manager = TraceManager.from_context(context)
    classifier = EventClassifier(context, rs, source_bus=manager.bus)
    circular = CircularEventBuffer(window_seconds=30.0)

    store: SessionStore | None = None
    session_id: str | None = None
    if output is not None:
        store = SessionStore(output)
        session_id = store.open_session(filter_text=filter_text or "")

    def on_classified(event: EventClassifiedEvent) -> None:
        if store is None:
            return
        store.append_alert(
            rule_id=event.rule_id,
            severity=event.severity,
            title=event.title,
            event_rowid=None,
            labels=event.labels,
        )
        if auto_inspect and event.severity == "critical" and event.source_event.process:
            pid_to_inspect = event.source_event.process.pid
            try:
                snap = ProcessInspector(pid_to_inspect).capture()
                store.append_snapshot(
                    f"inspect.pid_{pid_to_inspect}",
                    {
                        "pid": snap.pid,
                        "status": snap.status,
                        "cmdline": snap.cmdline,
                        "exe": snap.exe,
                        "fds": snap.fds[:50],
                        "maps": snap.maps[:50],
                        "namespaces": snap.namespaces,
                    },
                )
            except Exception:  # noqa: BLE001
                pass

    context.events.subscribe(EventClassifiedEvent, on_classified)

    probes = [ProbeSpec(category=EventCategory.SYSCALL_RAW, probe_type=ProbeType.TRACEPOINT)]
    try:
        await manager.start(probes, filter_expr=filt)
    except MonitorError as e:
        console.print(f"[red]{e}[/red]")
        if store is not None:
            store.close()
        return

    # Feed every event into the circular buffer so that critical alerts
    # can flush pre-event context into the session store.
    raw_sub = manager.bus.subscribe()

    async def _pump_circular() -> None:
        while True:
            ev = await raw_sub.get(timeout=0.2)
            if ev is None:
                continue
            circular.append(ev)
            if store is not None and any(
                cls.get("severity") == "critical"
                for cls in ev.metadata.get("classifications", [])
            ):
                store.append_snapshot(
                    "circular_flush",
                    {
                        "trigger_rule_ids": [
                            cls["rule_id"] for cls in ev.metadata.get("classifications", [])
                        ],
                        "events": [
                            {
                                "pid": e.process.pid if e.process else 0,
                                "comm": e.process.comm if e.process else "",
                                "syscall": e.syscall_name,
                                "wall_ns": e.wall_clock_ns,
                            }
                            for e in circular.dump()
                        ],
                    },
                )

    pump_task = asyncio.create_task(_pump_circular())
    await classifier.start()

    renderer = LiveRenderer(console=console)
    classified_sub = classifier.bus.subscribe()
    try:
        stats = await renderer.stream(classified_sub, duration=float(duration))
    finally:
        pump_task.cancel()
        try:
            await pump_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        classifier.bus.unsubscribe(classified_sub)
        await classifier.stop()
        manager.bus.unsubscribe(raw_sub)
        await manager.stop()
        if store is not None:
            store.close()
        context.events.unsubscribe(EventClassifiedEvent, on_classified)

    console.print(f"[dim]{format_stats_summary(stats, classified_sub)}[/dim]")
    if session_id is not None:
        console.print(f"[green]Session {session_id} persisted to {output}[/green]")
