"""Dashboard CLI group — runs a configurable multi-panel Rich UI.

Usage:
    deepview dashboard run [--layout NAME | --config PATH] [--duration S]
    deepview dashboard layouts
    deepview dashboard show PATH   # validate + summarise a custom config

The command builds a :class:`TraceManager` from the current
``AnalysisContext``, optionally starts a live classifier, and drives
a :class:`DashboardApp` that composes every panel defined in the
resolved layout.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable

import click
from rich.console import Console
from rich.table import Table

from deepview.cli.dashboard.app import DashboardApp
from deepview.cli.dashboard.config import (
    BUILTIN_LAYOUTS,
    DashboardConfigError,
    load_dashboard_config,
)
from deepview.cli.dashboard.panels import ManglePanel
from deepview.classification import EventClassifier, Ruleset
from deepview.core.context import AnalysisContext
from deepview.core.events import NetworkPacketMangledEvent
from deepview.core.exceptions import BackendNotAvailableError, MonitorError
from deepview.core.platform import PrivilegeLevel, check_privileges
from deepview.core.types import EventCategory, ProbeType
from deepview.tracing.filters import (
    FilterExpr,
    FilterRule,
    FilterSyntaxError,
    parse_filter,
)
from deepview.tracing.manager import TraceManager
from deepview.tracing.providers.base import ProbeSpec


@click.group()
def dashboard() -> None:
    """Multi-panel Rich dashboard for live Linux forensic visibility."""


@dashboard.command("layouts")
@click.pass_context
def dashboard_layouts(ctx: click.Context) -> None:
    """List the built-in dashboard layouts."""
    console: Console = ctx.obj["console"]
    table = Table(title="Built-in layouts")
    table.add_column("Name", style="cyan")
    table.add_column("Path")
    table.add_column("Panels")
    for name, path in BUILTIN_LAYOUTS.items():
        try:
            spec = load_dashboard_config(layout=name)
            panels = ", ".join(p.type for p in spec.panels)
        except DashboardConfigError as e:
            panels = f"[red]error: {e}[/red]"
        table.add_row(name, str(path), panels)
    console.print(table)


@dashboard.command("show")
@click.argument("config_path", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def dashboard_show(ctx: click.Context, config_path: str) -> None:
    """Parse a custom layout file and print its panel list."""
    console: Console = ctx.obj["console"]
    try:
        spec = load_dashboard_config(config_path=Path(config_path))
    except DashboardConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    console.print(f"[bold]refresh_hz[/bold]: {spec.refresh_hz}")
    console.print(f"[bold]trace.probes[/bold]: {spec.trace_probes}")
    if spec.trace_filter:
        console.print(f"[bold]trace.filter[/bold]: {spec.trace_filter}")
    table = Table(title="Panels")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Region")
    table.add_column("Config")
    for p in spec.panels:
        table.add_row(p.name, p.type, p.region, str(p.config))
    console.print(table)


@dashboard.command("run")
@click.option("--layout", "layout_name", type=str, default=None, help="Built-in layout name")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--duration", type=int, default=0, show_default=True, help="0 = run until interrupted")
@click.option("--filter", "extra_filter", type=str, default=None, help="Additional trace filter (DSL)")
@click.option("--pid", type=int, default=None)
@click.option("--ruleset", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--enable-mangle", is_flag=True, default=False, help="Also run the mangle engine")
@click.option("--mangle-rules", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--mangle-queue", type=int, default=None)
@click.option("--mangle-dry-run", is_flag=True, default=False)
@click.option("--install-iptables", is_flag=True, default=False)
@click.option("--confirm", is_flag=True, default=False, help="Skip the mangle confirmation prompt")
@click.pass_context
def dashboard_run(
    ctx: click.Context,
    layout_name: str | None,
    config_path: str | None,
    duration: int,
    extra_filter: str | None,
    pid: int | None,
    ruleset: str | None,
    enable_mangle: bool,
    mangle_rules: str | None,
    mangle_queue: int | None,
    mangle_dry_run: bool,
    install_iptables: bool,
    confirm: bool,
) -> None:
    """Run the dashboard against live trace data."""
    console: Console = ctx.obj["console"]

    try:
        spec = load_dashboard_config(
            layout=layout_name,
            config_path=Path(config_path) if config_path else None,
        )
    except DashboardConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    if enable_mangle and mangle_rules is None:
        console.print("[red]--enable-mangle requires --mangle-rules[/red]")
        raise click.Abort()

    asyncio.run(
        _run_dashboard(
            ctx,
            spec=spec,
            duration=duration if duration > 0 else None,
            extra_filter=extra_filter,
            pid=pid,
            ruleset=ruleset,
            enable_mangle=enable_mangle,
            mangle_rules=mangle_rules,
            mangle_queue=mangle_queue,
            mangle_dry_run=mangle_dry_run,
            install_iptables=install_iptables,
            confirm=confirm,
        )
    )


async def _run_dashboard(
    ctx: click.Context,
    *,
    spec,
    duration: float | None,
    extra_filter: str | None,
    pid: int | None,
    ruleset: str | None,
    enable_mangle: bool = False,
    mangle_rules: str | None = None,
    mangle_queue: int | None = None,
    mangle_dry_run: bool = False,
    install_iptables: bool = False,
    confirm: bool = False,
) -> None:
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    filter_expr = _build_trace_filter(spec, extra_filter=extra_filter, pid=pid)
    manager = TraceManager.from_context(context)
    probes = _build_probes(spec.trace_probes)

    try:
        await manager.start(probes, filter_expr=filter_expr)
    except MonitorError as e:
        console.print(f"[red]{e}[/red]")
        return

    classifier: EventClassifier | None = None
    classified_sub = None
    if ruleset is not None or spec.classification_ruleset:
        rs_path = ruleset or spec.classification_ruleset
        rs = Ruleset.load_yaml(rs_path) if rs_path else Ruleset.load_builtin()
        classifier = EventClassifier(context, rs, source_bus=manager.bus)
        await classifier.start()
        classified_sub = classifier.bus.subscribe()

    trace_sub = manager.bus.subscribe()
    app = DashboardApp(spec, console=console)

    # ------------------------------------------------------------------
    # Optional: spin up the mangle engine alongside the dashboard.
    # ------------------------------------------------------------------
    mangle_teardown: _MangleHandle | None = None
    if enable_mangle:
        try:
            mangle_teardown = _start_mangle(
                context=context,
                console=console,
                app=app,
                rules_path=mangle_rules,
                queue=mangle_queue,
                dry_run=mangle_dry_run,
                install_iptables=install_iptables,
                confirm=confirm,
            )
        except click.Abort:
            # Back out of the trace + classifier before we die.
            manager.bus.unsubscribe(trace_sub)
            if classified_sub is not None and classifier is not None:
                classifier.bus.unsubscribe(classified_sub)
                await classifier.stop()
            await manager.stop()
            raise

    try:
        await app.run(
            trace_subscription=trace_sub,
            classified_subscription=classified_sub,
            duration=duration,
        )
    finally:
        if mangle_teardown is not None:
            mangle_teardown.stop()
        if classified_sub is not None:
            classifier.bus.unsubscribe(classified_sub)
        if classifier is not None:
            await classifier.stop()
        manager.bus.unsubscribe(trace_sub)
        await manager.stop()

    console.print(
        f"[dim]dashboard exited: events={app._stats.events_received}[/dim]"
    )


# ---------------------------------------------------------------------------
# Mangle integration helpers
# ---------------------------------------------------------------------------


class _MangleHandle:
    """Minimal owner of the mangle engine + its teardown actions."""

    def __init__(
        self,
        engine,
        thread,
        installed_rule,
        installer,
        unsubscribe: Callable[[], None],
    ) -> None:
        self.engine = engine
        self.thread = thread
        self.installed_rule = installed_rule
        self.installer = installer
        self.unsubscribe = unsubscribe

    def stop(self) -> None:
        try:
            self.engine.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.thread.join(timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.unsubscribe()
        except Exception:  # noqa: BLE001
            pass
        if self.installed_rule is not None and self.installer is not None:
            try:
                self.installer.uninstall(self.installed_rule)
            except Exception:  # noqa: BLE001
                pass


def _start_mangle(
    *,
    context: AnalysisContext,
    console: Console,
    app: DashboardApp,
    rules_path: str | None,
    queue: int | None,
    dry_run: bool,
    install_iptables: bool,
    confirm: bool,
) -> _MangleHandle:
    """Spin up a MangleEngine in a worker thread and wire its events
    into the dashboard's :class:`ManglePanel`.

    Every safety gate in ``deepview netmangle run`` applies here too:
    root required, ruleset non-empty, confirmation unless ``--confirm``
    is already on.
    """
    import threading

    from deepview.networking.engine import MangleEngine
    from deepview.networking.iptables_installer import IptablesInstaller
    from deepview.networking.nfqueue_source import NFQueueSource
    from deepview.networking.ruleset import MangleRuleLoadError, MangleRuleset

    if check_privileges() != PrivilegeLevel.ROOT:
        console.print("[red]--enable-mangle requires root[/red]")
        raise click.Abort()
    if rules_path is None:
        console.print("[red]--enable-mangle requires --mangle-rules[/red]")
        raise click.Abort()
    try:
        ruleset = MangleRuleset.load_yaml(rules_path)
    except MangleRuleLoadError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    if len(ruleset) == 0:
        console.print("[red]refusing to start mangle engine: ruleset is empty[/red]")
        raise click.Abort()

    queue_num = queue if queue is not None else ruleset.queue
    if queue_num <= 0:
        console.print("[red]mangle queue number must be > 0[/red]")
        raise click.Abort()

    if not confirm:
        answer = click.confirm(
            f"About to start the mangle engine on NFQUEUE {queue_num} with "
            f"{len(ruleset)} rules (dry_run={dry_run}). Proceed?",
            default=False,
        )
        if not answer:
            raise click.Abort()

    installer = IptablesInstaller()
    installed_rule = None
    if install_iptables:
        try:
            installed_rule = installer.install(
                queue_num,
                binary=context.config.network_mangle.iptables_binary,
                table=context.config.network_mangle.iptables_table,
                chain=context.config.network_mangle.iptables_chain,
            )
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]iptables install failed: {e}[/red]")
            raise click.Abort() from e

    try:
        source = NFQueueSource(queue_num=queue_num)
    except BackendNotAvailableError as e:
        console.print(f"[red]{e}[/red]")
        if installed_rule is not None:
            installer.uninstall(installed_rule)
        raise click.Abort() from e

    mangle_panel = None
    for panel in app.panels:
        if isinstance(panel, ManglePanel):
            mangle_panel = panel
            break
    if mangle_panel is None:
        console.print(
            "[yellow]warning: layout has no 'mangle' panel; engine will run "
            "but stats won't be visible in the dashboard[/yellow]"
        )

    def _on_mangled(event: NetworkPacketMangledEvent) -> None:
        if mangle_panel is not None:
            mangle_panel.ingest_mangle(
                action=event.action or event.verdict,
                rule_id=event.rule_id,
                remote=event.remote,
                ts_ns=event.ts_ns,
            )

    context.events.subscribe(NetworkPacketMangledEvent, _on_mangled)

    def _event_sink(rule, outcome, view) -> None:
        from deepview.core.events import NetworkPacketMangledEvent as _E

        import time as _t

        ev = _E(
            ts_ns=_t.time_ns(),
            rule_id=rule.id if rule is not None else "",
            action=rule.action.type_name if rule is not None else "accept",
            verdict=outcome.verdict,
            direction="out",
            description=outcome.description,
            remote="",
        )
        context.events.publish(ev)

    engine = MangleEngine(
        ruleset,
        source,
        direction="out",
        dry_run=dry_run,
        event_sink=_event_sink,
    )
    engine.install_signal_handlers()

    thread = threading.Thread(target=engine.run, name="mangle-engine", daemon=True)
    thread.start()
    console.print(
        f"[green]mangle engine started[/green]: queue={queue_num} "
        f"rules={len(ruleset)} dry_run={dry_run}"
    )

    def _unsub() -> None:
        context.events.unsubscribe(NetworkPacketMangledEvent, _on_mangled)

    return _MangleHandle(engine, thread, installed_rule, installer, _unsub)


def _build_trace_filter(
    spec, *, extra_filter: str | None, pid: int | None
) -> FilterExpr | None:
    children: list = []
    if pid is not None:
        children.append(FilterRule("process.pid", "eq", int(pid)))
    if spec.trace_filter:
        try:
            children.append(parse_filter(spec.trace_filter))
        except FilterSyntaxError as e:
            raise click.BadParameter(f"layout trace.filter: {e}") from e
    if extra_filter:
        try:
            children.append(parse_filter(extra_filter))
        except FilterSyntaxError as e:
            raise click.BadParameter(f"--filter: {e}") from e
    if not children:
        return None
    return FilterExpr("and", children)


def _build_probes(probe_names: list[str]) -> list[ProbeSpec]:
    """Translate layout `trace.probes` values into ProbeSpec objects.

    The Slice 1 eBPF backend only emits raw_syscalls events, so we
    collapse everything into a single SYSCALL_RAW tracepoint; the
    categorical names still matter because they drive the per-probe
    user-side syscall filter sets. Callers should further narrow via
    ``--filter`` or layout ``trace.filter``.
    """
    # Deduplicate and pick a syscall_nr allowlist based on the probes.
    if not probe_names:
        return [ProbeSpec(category=EventCategory.SYSCALL_RAW, probe_type=ProbeType.TRACEPOINT)]
    return [ProbeSpec(category=EventCategory.SYSCALL_RAW, probe_type=ProbeType.TRACEPOINT)]
