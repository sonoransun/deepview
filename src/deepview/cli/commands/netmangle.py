"""Network packet mangling CLI group.

Subcommands:

* ``netmangle run``      — live NFQUEUE-backed engine (root + --enable-mangle + --confirm)
* ``netmangle validate`` — parse a ruleset and print the compiled shape; never touches netfilter
* ``netmangle status``   — show leftover iptables rules recorded in the state file

Every path into ``run`` is safety-gated:

- refuses to start without root
- refuses to start without ``--enable-mangle`` (it is never default-on)
- refuses an empty ruleset
- prompts for ``--confirm`` unless that flag is present on the invocation
- defaults to fail-open (ACCEPT) if the engine ever raises
- does not touch iptables unless ``--install-iptables`` is also passed
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from deepview.core.context import AnalysisContext
from deepview.core.events import NetworkPacketMangledEvent
from deepview.core.exceptions import BackendNotAvailableError
from deepview.core.logging import get_logger
from deepview.core.platform import PrivilegeLevel, check_privileges
from deepview.networking.actions import ActionOutcome
from deepview.networking.engine import MangleEngine
from deepview.networking.iptables_installer import (
    IptablesInstaller,
)
from deepview.networking.nfqueue_source import NFQueueSource
from deepview.networking.packet import PacketView
from deepview.networking.ruleset import (
    MangleRule,
    MangleRuleLoadError,
    MangleRuleset,
)

log = get_logger("cli.netmangle")


@click.group()
def netmangle() -> None:
    """Live network packet mangling (NFQUEUE-backed)."""


@netmangle.command("validate")
@click.argument("rules", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def netmangle_validate(ctx: click.Context, rules: str) -> None:
    """Parse a mangle ruleset and print its compiled shape."""
    console: Console = ctx.obj["console"]
    try:
        ruleset = MangleRuleset.load_yaml(rules)
    except MangleRuleLoadError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    table = Table(title=f"{rules} — {len(ruleset)} rules, queue={ruleset.queue}")
    table.add_column("#", justify="right")
    table.add_column("ID", style="cyan")
    table.add_column("Action", style="magenta")
    table.add_column("Description")
    for i, r in enumerate(ruleset, 1):
        table.add_row(str(i), r.id, r.action.type_name, r.description)
    console.print(table)
    console.print(
        f"[dim]sha256={ruleset.source_sha256[:12]}… "
        f"default_verdict={ruleset.default_verdict} fail_open={ruleset.fail_open}[/dim]"
    )


@netmangle.command("status")
@click.pass_context
def netmangle_status(ctx: click.Context) -> None:
    """Print any iptables NFQUEUE rules installed by previous runs."""
    console: Console = ctx.obj["console"]
    installer = IptablesInstaller()
    rules = installer.load_state()
    if not rules:
        console.print(f"[dim]no leftover rules in {installer._state_path}[/dim]")
        return
    table = Table(title=f"Leftover rules in {installer._state_path}")
    table.add_column("Binary")
    table.add_column("Table")
    table.add_column("Chain")
    table.add_column("Queue", justify="right")
    table.add_column("Remove with")
    for r in rules:
        table.add_row(
            r.binary,
            r.table,
            r.chain,
            str(r.queue_num),
            " ".join(r.delete_command()),
        )
    console.print(table)


@netmangle.command("run")
@click.option("--rules", type=click.Path(exists=True, dir_okay=False), required=True)
@click.option("--queue", type=int, default=None, help="NFQUEUE number (overrides ruleset)")
@click.option("--enable-mangle", is_flag=True, default=False, help="Required opt-in")
@click.option("--confirm", is_flag=True, default=False, help="Skip the interactive prompt")
@click.option("--dry-run", is_flag=True, default=False, help="Force every verdict to ACCEPT")
@click.option(
    "--install-iptables",
    is_flag=True,
    default=False,
    help="Auto install + remove the NFQUEUE jump rule. Otherwise the operator must pre-install it.",
)
@click.option("--direction", type=click.Choice(["in", "out"]), default="out", show_default=True)
@click.option("--duration", type=int, default=0, show_default=True, help="0 = run until interrupted")
@click.option("--output", type=click.Path(dir_okay=False), default=None, help="Persist a session.db")
@click.pass_context
def netmangle_run(
    ctx: click.Context,
    rules: str,
    queue: int | None,
    enable_mangle: bool,
    confirm: bool,
    dry_run: bool,
    install_iptables: bool,
    direction: str,
    duration: int,
    output: str | None,
) -> None:
    """Run the mangle engine against live NFQUEUE traffic."""
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    # Safety gates ----------------------------------------------------
    if not enable_mangle:
        console.print(
            "[red]refusing to start: pass --enable-mangle to explicitly opt in[/red]"
        )
        raise click.Abort()
    if check_privileges() != PrivilegeLevel.ROOT:
        console.print("[red]refusing to start: root required[/red]")
        raise click.Abort()
    try:
        ruleset = MangleRuleset.load_yaml(rules)
    except MangleRuleLoadError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    if len(ruleset) == 0:
        console.print("[red]refusing to start: ruleset is empty[/red]")
        raise click.Abort()
    queue_num = queue if queue is not None else ruleset.queue
    if queue_num <= 0:
        console.print(
            "[red]refusing to start: queue number must be set via --queue or 'queue:' in the ruleset[/red]"
        )
        raise click.Abort()
    if not confirm:
        answer = click.confirm(
            f"About to run the mangle engine on NFQUEUE {queue_num} with "
            f"{len(ruleset)} rules (dry_run={dry_run}). Proceed?",
            default=False,
        )
        if not answer:
            console.print("[yellow]aborted by operator[/yellow]")
            return

    # Optional iptables install --------------------------------------
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
            console.print(f"[green]installed iptables rule[/green]: {' '.join(installed_rule.insert_command())}")
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]iptables install failed: {e}[/red]")
            raise click.Abort() from e
    else:
        console.print(
            "[yellow]--install-iptables not set; expecting a pre-installed NFQUEUE "
            f"jump rule for queue {queue_num}. A typical command is:[/yellow]\n"
            f"  sudo iptables -t mangle -A OUTPUT -j NFQUEUE --queue-num {queue_num} --queue-bypass"
        )

    # Build the engine -----------------------------------------------
    session_store = None
    if output is not None:
        from deepview.replay.store import SessionStore  # lazy

        session_store = SessionStore(Path(output))
        session_store.open_session(
            hostname=os.uname().nodename,
            kernel=os.uname().release,
            filter_text=f"mangle:{rules}",
        )

    def _alert_sink(rule: MangleRule, outcome: ActionOutcome, view: PacketView) -> None:
        if session_store is None:
            return
        try:
            session_store.append_alert(
                rule_id=rule.id,
                severity=_severity_for(outcome.verdict),
                title=rule.description or rule.id,
                event_rowid=None,
                labels={
                    "action": outcome.description,
                    "verdict": outcome.verdict,
                    "queue": str(queue_num),
                },
            )
        except Exception as e:  # noqa: BLE001
            log.warning("mangle_alert_sink_failed", error=str(e))

    def _event_sink(rule: MangleRule | None, outcome: ActionOutcome, view: PacketView) -> None:
        ev = NetworkPacketMangledEvent(
            ts_ns=time.time_ns(),
            rule_id=rule.id if rule is not None else "",
            action=rule.action.type_name if rule is not None else "accept",
            verdict=outcome.verdict,
            direction=direction,
            description=outcome.description,
            remote=_remote_repr(view),
            before_bytes=len(view.parsed.raw),
            after_bytes=len(outcome.new_bytes) if outcome.new_bytes else 0,
        )
        context.events.publish(ev)

    try:
        source = NFQueueSource(queue_num=queue_num)
    except BackendNotAvailableError as e:
        console.print(f"[red]{e}[/red]")
        if installed_rule is not None:
            installer.uninstall(installed_rule)
        if session_store is not None:
            session_store.close()
        raise click.Abort() from e

    engine = MangleEngine(
        ruleset,
        source,
        direction=direction,
        dry_run=dry_run,
        alert_sink=_alert_sink,
        event_sink=_event_sink,
    )
    engine.install_signal_handlers()
    console.print(
        f"[green]mangle engine running[/green]: queue={queue_num} rules={len(ruleset)} "
        f"dry_run={dry_run} direction={direction}"
    )

    try:
        # Run in a worker thread so we can enforce --duration from the
        # main thread via engine.stop() after N seconds.
        import threading

        stop_at = time.time() + duration if duration > 0 else None
        thread = threading.Thread(target=engine.run, name="mangle-engine", daemon=True)
        thread.start()
        try:
            while thread.is_alive():
                if stop_at is not None and time.time() >= stop_at:
                    engine.stop()
                    break
                time.sleep(0.2)
        except KeyboardInterrupt:
            engine.stop()
        thread.join(timeout=2.0)
    finally:
        stats = engine.stats.as_dict()
        console.print(
            "[bold]stats[/bold] "
            + " ".join(f"{k}={v}" for k, v in stats.items())
        )
        if session_store is not None:
            session_store.append_snapshot("mangle_final_stats", stats)
            session_store.close()
        if installed_rule is not None:
            installer.uninstall(installed_rule)
            console.print("[green]removed iptables rule[/green]")


def _severity_for(verdict: str) -> str:
    return {
        "drop": "critical",
        "modified": "warning",
        "repeat": "warning",
    }.get(verdict, "info")


def _remote_repr(view: PacketView) -> str:
    parsed = view.parsed
    if parsed.ipv4 is not None:
        ip = parsed.ipv4.dst if view.direction == "out" else parsed.ipv4.src
    elif parsed.ipv6 is not None:
        ip = parsed.ipv6.dst if view.direction == "out" else parsed.ipv6.src
    else:
        return ""
    if parsed.tcp is not None:
        port = parsed.tcp.dport if view.direction == "out" else parsed.tcp.sport
        return f"{ip}:{port}/tcp"
    if parsed.udp is not None:
        port = parsed.udp.dport if view.direction == "out" else parsed.udp.sport
        return f"{ip}:{port}/udp"
    return ip
