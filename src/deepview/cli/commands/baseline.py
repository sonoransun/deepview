"""``deepview baseline`` CLI group."""
from __future__ import annotations

import platform as _platform
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table


@click.group()
def baseline() -> None:
    """Baseline capture / diff commands."""


def _default_store(ctx: click.Context) -> Path:
    config = ctx.obj["context"].config
    return Path(config.cache_dir) / "snapshots.db"


@baseline.command("capture")
@click.option("--host-id", default="", help="Host identifier (defaults to hostname)")
@click.option("--store", "store_path", type=click.Path(), default=None, help="Snapshot store path")
@click.option(
    "--critical-file",
    "critical_files",
    multiple=True,
    help="Critical file path to hash (repeatable)",
)
@click.option(
    "--memory-image",
    "memory_image",
    type=click.Path(exists=False),
    default=None,
    help="Memory dump to page-hash into the snapshot",
)
@click.pass_context
def capture(
    ctx: click.Context,
    host_id: str,
    store_path: str | None,
    critical_files: tuple[str, ...],
    memory_image: str | None,
) -> None:
    """Capture a snapshot of the current host state."""
    from deepview.baseline import HostSnapshot, SnapshotStore

    console: Console = ctx.obj["console"]
    sp = Path(store_path) if store_path else _default_store(ctx)
    store = SnapshotStore(sp)
    hid = host_id or _platform.node() or "localhost"
    snap = HostSnapshot.capture_current(
        host_id=hid,
        critical_paths=[Path(p) for p in critical_files] or None,
        include_memory=Path(memory_image) if memory_image else None,
    )
    store.save(snap)
    console.print(
        f"[green]Captured snapshot [bold]{snap.snapshot_id}[/bold] for host [bold]{hid}[/bold][/green]"
    )
    console.print(
        f"  processes={len(snap.processes)} modules={len(snap.modules)} "
        f"network={len(snap.network)} persistence={len(snap.persistence)} "
        f"kernel_modules={len(snap.kernel_modules)}"
    )


@baseline.command("list")
@click.option("--host-id", default="", help="Limit to one host")
@click.option("--store", "store_path", type=click.Path(), default=None)
@click.pass_context
def list_snapshots(ctx: click.Context, host_id: str, store_path: str | None) -> None:
    from deepview.baseline import SnapshotStore

    console: Console = ctx.obj["console"]
    sp = Path(store_path) if store_path else _default_store(ctx)
    store = SnapshotStore(sp)
    snaps = store.list_snapshots(host_id or None)
    table = Table(title="Snapshots")
    table.add_column("ID", style="cyan")
    table.add_column("Host")
    table.add_column("Captured")
    table.add_column("Platform")
    for snap in snaps:
        table.add_row(
            snap["snapshot_id"],
            snap["host_id"],
            snap["captured_at"],
            snap["platform"],
        )
    console.print(table)


@baseline.command("diff")
@click.argument("base_id")
@click.argument("current_id")
@click.option("--store", "store_path", type=click.Path(), default=None)
@click.pass_context
def diff(ctx: click.Context, base_id: str, current_id: str, store_path: str | None) -> None:
    """Diff two stored snapshots and emit BaselineDeviationEvents."""
    from deepview.baseline import DeviationPublisher, SnapshotDiffer, SnapshotStore
    from deepview.baseline.rules import run_rules

    console: Console = ctx.obj["console"]
    context = ctx.obj["context"]
    sp = Path(store_path) if store_path else _default_store(ctx)
    store = SnapshotStore(sp)
    base_snap = store.load(base_id)
    current_snap = store.load(current_id)
    delta = SnapshotDiffer().diff(base_snap, current_snap)
    publisher = DeviationPublisher(context.events)
    published = publisher.publish(delta)
    findings = run_rules(delta)
    for finding in findings:
        context.correlation._dispatch_finding(finding)  # noqa: SLF001
    table = Table(title=f"Delta: {base_id[:8]} -> {current_id[:8]}")
    table.add_column("Category")
    table.add_column("Change")
    for category, change in (
        ("processes: spawned", len(delta.processes.spawned)),
        ("processes: exited", len(delta.processes.exited)),
        ("processes: reparented", len(delta.processes.reparented)),
        ("kernel_modules: loaded", len(delta.kernel_modules.loaded)),
        ("kernel_modules: unloaded", len(delta.kernel_modules.unloaded)),
        ("network: new listeners", len(delta.network.new_listeners)),
        ("persistence: added", len(delta.persistence.added)),
        ("persistence: removed", len(delta.persistence.removed)),
        ("users: added", len(delta.new_users)),
        ("users: removed", len(delta.removed_users)),
        ("files: modified", len(delta.filesystem.modified)),
    ):
        if change:
            table.add_row(category, str(change))
    console.print(table)
    console.print(f"[cyan]Published {published} BaselineDeviationEvents[/cyan]")
    if findings:
        rules_table = Table(title="Findings")
        rules_table.add_column("Rule", style="cyan")
        rules_table.add_column("Severity")
        rules_table.add_column("MITRE")
        rules_table.add_column("Description")
        for f in findings:
            rules_table.add_row(
                f.rule_id,
                f.severity.value,
                ",".join(f.mitre_techniques),
                f.description[:80],
            )
        console.print(rules_table)
