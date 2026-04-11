"""Live system tracing commands.

These subcommands build a :class:`~deepview.tracing.manager.TraceManager`
from the current :class:`~deepview.core.context.AnalysisContext`, register
domain-appropriate probes, subscribe to the event bus, and stream events
through a ``LiveRenderer`` until ``--duration`` elapses or the user sends
SIGINT. Filter expressions passed to ``--filter`` are parsed through the
text DSL when Slice 3 lands; for now they accept the convenience
helpers on :class:`FilterExpr`.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Iterable

import click

from deepview.cli.formatters.live import LiveRenderer, format_stats_summary
from deepview.core.context import AnalysisContext
from deepview.core.exceptions import MonitorError
from deepview.core.types import EventCategory, ProbeType
from deepview.tracing.filters import FilterExpr, FilterRule, FilterSyntaxError, parse_filter
from deepview.tracing.linux.syscalls import (
    FILESYSTEM_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    resolve_nrs,
)
from deepview.tracing.manager import TraceManager
from deepview.tracing.providers.base import ProbeSpec


def _build_filter(
    *,
    pid: int | None,
    uid: int | None,
    comms: Iterable[str] | None,
    syscall_names: Iterable[str] | None,
    syscall_nrs: Iterable[int] | None,
    expr_text: str | None = None,
) -> FilterExpr | None:
    """Assemble a top-level AND filter from CLI option values.

    If ``expr_text`` is supplied it is parsed with :func:`parse_filter`
    and merged with the option-derived predicates via a top-level AND.
    """
    children: list[FilterRule | FilterExpr] = []
    if pid is not None:
        children.append(FilterRule("process.pid", "eq", int(pid)))
    if uid is not None:
        children.append(FilterRule("process.uid", "eq", int(uid)))
    comm_list = [c for c in (comms or []) if c]
    if comm_list:
        children.append(FilterRule("process.comm", "in", comm_list))
    name_list = [n for n in (syscall_names or []) if n]
    if name_list:
        children.append(FilterRule("syscall_name", "in", name_list))
    nr_list = list(syscall_nrs or [])
    if nr_list:
        children.append(FilterRule("syscall_nr", "in", nr_list))
    if expr_text:
        try:
            parsed = parse_filter(expr_text)
        except FilterSyntaxError as e:
            raise click.BadParameter(f"invalid --filter expression: {e}") from e
        children.append(parsed)
    if not children:
        return None
    return FilterExpr("and", children)


async def _run_trace(
    ctx: click.Context,
    *,
    probes: list[ProbeSpec],
    filter_expr: FilterExpr | None,
    duration: int,
    override_source: str | None = None,
) -> None:
    console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    manager = TraceManager.from_context(context)
    subscription = manager.bus.subscribe(filter_expr=filter_expr)

    # If trace custom, inject the user's BPF source into the eBPF backend
    # before start() so _generate_bpf_source is bypassed.
    if override_source is not None:
        from deepview.tracing.providers.ebpf import EBPFBackend

        backends = manager.create_backends()
        for b in backends:
            if isinstance(b, EBPFBackend):
                b.set_override_source(override_source)
        manager.set_backend_override(backends)

    try:
        await manager.start(probes, filter_expr=filter_expr)
    except MonitorError as e:
        console.print(f"[red]{e}[/red]")
        return

    renderer = LiveRenderer(console=console)
    try:
        stats = await renderer.stream(subscription, duration=float(duration))
    finally:
        await manager.stop()
        manager.bus.unsubscribe(subscription)

    console.print(f"[dim]{format_stats_summary(stats, subscription)}[/dim]")


@click.group()
def trace() -> None:
    """System call and event tracing."""


_DURATION = click.option(
    "--duration",
    type=int,
    default=30,
    show_default=True,
    help="Duration in seconds. Use 0 to run until interrupted.",
)
_PID = click.option("--pid", type=int, default=None, help="Filter by PID")
_UID = click.option("--uid", type=int, default=None, help="Filter by UID")
_COMM = click.option("--comm", multiple=True, help="Filter by process comm (repeatable)")
_FILTER = click.option("--filter", "filter_expr", type=str, default=None, help="Filter expression (Slice 3)")


@trace.command()
@_DURATION
@_PID
@_UID
@_COMM
@click.option("--syscall", multiple=True, help="Syscall name(s) to trace")
@_FILTER
@click.pass_context
def syscall(ctx, duration, pid, uid, comm, syscall, filter_expr):
    """Trace system calls (raw_syscalls:sys_enter on Linux)."""
    filt = _build_filter(
        pid=pid,
        uid=uid,
        comms=comm,
        syscall_names=list(syscall),
        syscall_nrs=resolve_nrs(set(syscall)) if syscall else None,
        expr_text=filter_expr,
    )
    probes = [ProbeSpec(category=EventCategory.SYSCALL_RAW, probe_type=ProbeType.TRACEPOINT)]
    asyncio.run(_run_trace(ctx, probes=probes, filter_expr=filt, duration=duration))


@trace.command()
@_DURATION
@_PID
@_UID
@_COMM
@_FILTER
@click.pass_context
def network(ctx, duration, pid, uid, comm, filter_expr):
    """Trace network syscalls (socket, connect, accept, send, recv...)."""
    filt = _build_filter(
        pid=pid,
        uid=uid,
        comms=comm,
        syscall_names=list(NETWORK_SYSCALLS),
        syscall_nrs=resolve_nrs(NETWORK_SYSCALLS),
        expr_text=filter_expr,
    )
    probes = [ProbeSpec(category=EventCategory.NETWORK, probe_type=ProbeType.TRACEPOINT)]
    asyncio.run(_run_trace(ctx, probes=probes, filter_expr=filt, duration=duration))


@trace.command()
@_DURATION
@_PID
@_UID
@_COMM
@_FILTER
@click.pass_context
def filesystem(ctx, duration, pid, uid, comm, filter_expr):
    """Trace filesystem syscalls (open, read, write, unlink, rename...)."""
    filt = _build_filter(
        pid=pid,
        uid=uid,
        comms=comm,
        syscall_names=list(FILESYSTEM_SYSCALLS),
        syscall_nrs=resolve_nrs(FILESYSTEM_SYSCALLS),
        expr_text=filter_expr,
    )
    probes = [ProbeSpec(category=EventCategory.FILE_IO, probe_type=ProbeType.TRACEPOINT)]
    asyncio.run(_run_trace(ctx, probes=probes, filter_expr=filt, duration=duration))


@trace.command()
@_DURATION
@_PID
@_UID
@_COMM
@_FILTER
@click.pass_context
def process(ctx, duration, pid, uid, comm, filter_expr):
    """Trace process lifecycle (fork, clone, execve, exit, kill, ptrace...)."""
    filt = _build_filter(
        pid=pid,
        uid=uid,
        comms=comm,
        syscall_names=list(PROCESS_SYSCALLS),
        syscall_nrs=resolve_nrs(PROCESS_SYSCALLS),
        expr_text=filter_expr,
    )
    probes = [ProbeSpec(category=EventCategory.PROCESS, probe_type=ProbeType.TRACEPOINT)]
    asyncio.run(_run_trace(ctx, probes=probes, filter_expr=filt, duration=duration))


@trace.command()
@click.option("--program", type=click.Path(exists=True, dir_okay=False), required=True, help="BCC BPF C source file")
@_DURATION
@_PID
@_UID
@_COMM
@click.pass_context
def custom(ctx, program, duration, pid, uid, comm):
    """Run a custom BCC BPF program and stream its ``events`` perf buffer.

    The program must declare ``BPF_PERF_OUTPUT(events)`` and submit a
    struct that matches the default ``event_t`` layout defined in
    ``providers/ebpf.py``; otherwise the decoded events will be garbage.
    """
    source = Path(program).read_text()
    filt = _build_filter(pid=pid, uid=uid, comms=comm, syscall_names=None, syscall_nrs=None)
    probes: list[ProbeSpec] = []
    asyncio.run(_run_trace(ctx, probes=probes, filter_expr=filt, duration=duration, override_source=source))
