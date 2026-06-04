"""Virtual-machine introspection CLI group.

Subcommands:

* ``vm list``     — enumerate VMs visible to the available hypervisor connectors.
* ``vm snapshot`` — create a snapshot of a VM.
* ``vm extract``  — dump a VM's memory to a file.
* ``vm analyze``  — snapshot, extract memory, and run an analysis plugin in one step.

Connectors degrade gracefully via :meth:`VMConnector.is_available`, so no live
hypervisor is required for the commands to import / dispatch. When no connector
is usable (or a hypervisor operation fails) the command prints a clear ``[red]``
message and raises :class:`click.Abort` rather than emitting a traceback.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.table import Table

from deepview.core.exceptions import VMError

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext


@click.group()
def vm() -> None:
    """Virtual machine operations."""


def _resolve_hypervisor(name: str) -> str:
    """Map the CLI ``--hypervisor`` choice onto a connector name."""
    # The connectors register themselves as "qemu" / "vbox" / "vmware";
    # "auto" is understood directly by ``VMManager.get_connector``.
    return name


@vm.command("list")
@click.option(
    "--hypervisor",
    type=click.Choice(["qemu", "vmware", "vbox", "auto"]),
    default="auto",
    show_default=True,
)
@click.pass_context
def list_vms(ctx: click.Context, hypervisor: str) -> None:
    """List available virtual machines."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    manager = context.vm
    available = manager.available_connectors
    if not available:
        console.print(
            "[yellow]No VM connector available. VM introspection requires a "
            "hypervisor (libvirt, VirtualBox, or VMware). "
            "Run 'deepview doctor' to check.[/yellow]"
        )
        return

    try:
        vms = manager.list_vms(_resolve_hypervisor(hypervisor))
    except VMError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001 - surface any connector failure cleanly
        console.print(f"[red]Failed to list VMs: {e}[/red]")
        raise click.Abort() from e

    table = Table(title=f"Virtual machines (connectors: {', '.join(available)})")
    table.add_column("VM ID", style="cyan")
    table.add_column("Name")
    table.add_column("State")
    table.add_column("Hypervisor")
    table.add_column("Memory (MB)", justify="right")

    if not vms:
        console.print("[dim]No virtual machines found.[/dim]")
        return

    for info in vms:
        table.add_row(
            info.vm_id,
            info.name,
            info.state,
            info.hypervisor,
            str(info.memory_mb),
        )
    console.print(table)


@vm.command()
@click.option("--vm-id", required=True, help="VM identifier")
@click.option("--name", required=True, help="Snapshot name")
@click.option(
    "--hypervisor",
    type=click.Choice(["qemu", "vmware", "vbox", "auto"]),
    default="auto",
    show_default=True,
)
@click.pass_context
def snapshot(ctx: click.Context, vm_id: str, name: str, hypervisor: str) -> None:
    """Create VM snapshot."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    console.print(f"[bold]Creating snapshot '{name}' for VM {vm_id}...[/bold]")
    try:
        snap = context.vm.snapshot(vm_id, name, _resolve_hypervisor(hypervisor))
    except VMError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Snapshot failed: {e}[/red]")
        raise click.Abort() from e

    console.print(
        f"[green]created snapshot[/green] {snap.snapshot_id!r} for VM {snap.vm_id} "
        f"(memory={'yes' if snap.has_memory else 'no'})"
    )


@vm.command()
@click.option("--vm-id", required=True, help="VM identifier")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output path")
@click.option(
    "--hypervisor",
    type=click.Choice(["qemu", "vmware", "vbox", "auto"]),
    default="auto",
    show_default=True,
)
@click.pass_context
def extract(ctx: click.Context, vm_id: str, output: str, hypervisor: str) -> None:
    """Extract VM memory/state."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    console.print(f"[bold]Extracting memory from VM {vm_id}...[/bold]")
    try:
        out_path = context.vm.extract_memory(
            vm_id, Path(output), _resolve_hypervisor(hypervisor)
        )
    except VMError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Memory extraction failed: {e}[/red]")
        raise click.Abort() from e

    console.print(f"[green]extracted[/green] VM {vm_id} memory -> {out_path}")


@vm.command("analyze")
@click.option("--vm-id", required=True, help="VM identifier")
@click.option("--plugin", "-p", type=str, required=True, help="Analysis plugin")
@click.option("--name", default="deepview-analyze", show_default=True, help="Snapshot name")
@click.option("--output", "-o", type=click.Path(), default=None, help="Memory dump path")
@click.option(
    "--hypervisor",
    type=click.Choice(["qemu", "vmware", "vbox", "auto"]),
    default="auto",
    show_default=True,
)
@click.pass_context
def vm_analyze(
    ctx: click.Context,
    vm_id: str,
    plugin: str,
    name: str,
    output: str | None,
    hypervisor: str,
) -> None:
    """Snapshot a VM, extract its memory, and run an analysis plugin."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    hv = _resolve_hypervisor(hypervisor)
    dump_path = Path(output) if output else Path(f"{vm_id}-{name}.dump")

    console.print(f"[bold]Analyzing VM {vm_id} with plugin {plugin}...[/bold]")
    try:
        snap = context.vm.snapshot(vm_id, name, hv)
        console.print(f"  [dim]snapshot:[/dim] {snap.snapshot_id}")
        mem_path = context.vm.extract_memory(vm_id, dump_path, hv)
        console.print(f"  [dim]memory:[/dim] {mem_path}")
    except VMError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]VM analysis preparation failed: {e}[/red]")
        raise click.Abort() from e

    # Register the dump as a layer (best-effort) and run the requested plugin.
    plugin_config = {"image_path": str(mem_path)}
    try:
        plugin_instance = context.plugins.instantiate(plugin, config=plugin_config)
        result = plugin_instance.run()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Plugin {plugin!r} failed: {e}[/red]")
        raise click.Abort() from e

    table = Table(title=f"Plugin: {plugin}", show_lines=True)
    for col in result.columns:
        table.add_column(col, style="cyan")
    for row in result.rows:
        table.add_row(*(str(row.get(col, "")) for col in result.columns))
    console.print(table)
    console.print(f"\n[green]Analysis complete. {len(result.rows)} rows returned.[/green]")
