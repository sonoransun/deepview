"""Session record & replay CLI group.

Sibling to ``deepview trace`` — the ``record`` subcommand drives a
:class:`TraceManager` + :class:`SessionRecorder`, while ``list`` /
``show`` / ``play`` / ``export`` operate on an existing session file.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from deepview.cli.formatters.live import LiveRenderer, format_stats_summary
from deepview.classification import EventClassifier, Ruleset
from deepview.core.context import AnalysisContext
from deepview.core.exceptions import MonitorError
from deepview.core.types import EventCategory, ProbeType
from deepview.replay.circular import CircularEventBuffer
from deepview.replay.recorder import SessionRecorder
from deepview.replay.replayer import SessionReplayer
from deepview.replay.store import SessionReader, SessionStore
from deepview.tracing.filters import FilterExpr, FilterRule, FilterSyntaxError, parse_filter
from deepview.tracing.manager import TraceManager
from deepview.tracing.providers.base import ProbeSpec


@click.group()
def replay() -> None:
    """Record live trace sessions and replay them on demand."""


@replay.command("record")
@click.option("--output", "output", type=click.Path(dir_okay=False), required=True, help="Session database file")
@click.option("--duration", type=int, default=30, show_default=True, help="Record duration in seconds")
@click.option("--pid", type=int, default=None, help="Filter by PID")
@click.option("--filter", "filter_expr", type=str, default=None, help="Filter expression (DSL)")
@click.option("--snapshot-every", type=float, default=0.0, help="Seconds between /proc snapshots (0 = none)")
@click.option("--circular-seconds", type=float, default=60.0, show_default=True)
@click.pass_context
def replay_record(ctx, output, duration, pid, filter_expr, snapshot_every, circular_seconds):
    """Record a live trace session into a SQLite database."""
    asyncio.run(
        _record(
            ctx,
            output=Path(output),
            duration=duration,
            pid=pid,
            filter_text=filter_expr,
            snapshot_every=snapshot_every,
            circular_seconds=circular_seconds,
        )
    )


async def _record(
    ctx: click.Context,
    *,
    output: Path,
    duration: int,
    pid: int | None,
    filter_text: str | None,
    snapshot_every: float,
    circular_seconds: float,
) -> None:
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
    store = SessionStore(output)
    circular = CircularEventBuffer(window_seconds=circular_seconds)
    recorder = SessionRecorder(manager.bus, store, filter_text=filter_text or "", circular=circular)
    probes = [ProbeSpec(category=EventCategory.SYSCALL_RAW, probe_type=ProbeType.TRACEPOINT)]

    try:
        await manager.start(probes, filter_expr=filt)
    except MonitorError as e:
        console.print(f"[red]{e}[/red]")
        store.close()
        return

    session_id = await recorder.start()
    console.print(f"[green]Recording session {session_id}[/green] into [bold]{output}[/bold]")

    renderer = LiveRenderer(console=console)
    subscription = manager.bus.subscribe()
    try:
        stats = await renderer.stream(subscription, duration=float(duration))
    finally:
        manager.bus.unsubscribe(subscription)
        await recorder.stop()
        await manager.stop()
        store.close()

    console.print(f"[dim]{format_stats_summary(stats, subscription)}[/dim]")
    console.print(f"[green]Session closed.[/green] Run [bold]deepview replay list {output}[/bold]")


@replay.command("list")
@click.argument("session_db", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def replay_list(ctx, session_db):
    """List sessions stored in *session_db*."""
    console: Console = ctx.obj["console"]
    reader = SessionReader(Path(session_db))
    try:
        sessions = reader.list_sessions()
    finally:
        reader.close()
    if not sessions:
        console.print("[dim]no sessions found[/dim]")
        return
    table = Table(title=f"Sessions in {session_db}")
    table.add_column("ID", style="cyan")
    table.add_column("Started")
    table.add_column("Duration(s)")
    table.add_column("Events", justify="right")
    table.add_column("Alerts", justify="right")
    table.add_column("Dropped", justify="right")
    table.add_column("Filter")
    for s in sessions:
        duration = ((s.ended_ns or s.started_ns) - s.started_ns) / 1e9
        table.add_row(
            s.id,
            str(s.started_ns),
            f"{duration:.1f}",
            str(s.event_count),
            str(s.alert_count),
            str(s.dropped),
            (s.filter_text or "")[:60],
        )
    console.print(table)


@replay.command("show")
@click.argument("session_db", type=click.Path(exists=True, dir_okay=False))
@click.option("--session", "session_id", type=str, default=None)
@click.option("--pid", type=int, default=None)
@click.option("--category", type=str, default=None)
@click.option("--limit", type=int, default=100, show_default=True)
@click.pass_context
def replay_show(ctx, session_db, session_id, pid, category, limit):
    """Print stored events as a table."""
    console: Console = ctx.obj["console"]
    reader = SessionReader(Path(session_db))
    try:
        if session_id is None:
            sessions = reader.list_sessions()
            if not sessions:
                console.print("[dim]no sessions[/dim]")
                return
            session_id = sessions[-1].id
        table = Table(title=f"Events (session {session_id})")
        for col in ("TS", "PID", "Comm", "Cat", "Syscall", "Args"):
            table.add_column(col, overflow="fold")
        shown = 0
        for ev in reader.iter_events(session_id=session_id, pid=pid, category=category):
            if shown >= limit:
                break
            shown += 1
            args_s = ", ".join(f"{k}={v}" for k, v in list(ev.args.items())[:4])
            table.add_row(
                str(ev.wall_clock_ns),
                str(ev.process.pid if ev.process else 0),
                ev.process.comm if ev.process else "",
                ev.category.value if ev.category else "",
                ev.syscall_name or str(ev.syscall_nr),
                args_s,
            )
        console.print(table)
    finally:
        reader.close()


@replay.command("play")
@click.argument("session_db", type=click.Path(exists=True, dir_okay=False))
@click.option("--session", "session_id", type=str, default=None)
@click.option("--speed", type=float, default=0.0, show_default=True, help="0 = instant, 1 = realtime, N = Nx")
@click.option("--ruleset", type=click.Path(exists=True, dir_okay=False), default=None, help="Apply a classification ruleset during replay")
@click.pass_context
def replay_play(ctx, session_db, session_id, speed, ruleset):
    """Replay a stored session through an optional ruleset."""
    asyncio.run(_play(ctx, Path(session_db), session_id, speed, ruleset))


async def _play(ctx, session_db: Path, session_id: str | None, speed: float, ruleset_path: str | None) -> None:
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]
    reader = SessionReader(session_db)
    if session_id is None:
        sessions = reader.list_sessions()
        if not sessions:
            console.print("[dim]no sessions[/dim]")
            reader.close()
            return
        session_id = sessions[-1].id

    replayer = SessionReplayer(reader, session_id, speed=speed)
    classifier: EventClassifier | None = None
    if ruleset_path is not None:
        rs = Ruleset.load_yaml(ruleset_path)
        classifier = EventClassifier(context, rs, source_bus=replayer.bus)
        await classifier.start()

    renderer = LiveRenderer(console=console)
    sink_bus = classifier.bus if classifier is not None else replayer.bus
    subscription = sink_bus.subscribe()

    try:
        play_task = asyncio.create_task(replayer.play(step=(speed == 0.0)))
        await renderer.stream(subscription, duration=None)
        await play_task
    finally:
        sink_bus.unsubscribe(subscription)
        if classifier is not None:
            await classifier.stop()
        reader.close()

    console.print(
        f"[dim]replayed={replayer.stats.events_published} read={replayer.stats.events_read}[/dim]"
    )
