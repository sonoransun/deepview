"""On-demand inspection commands.

Sibling to ``deepview trace`` and ``deepview replay``. These
subcommands answer "show me everything about X *right now*" for
processes, files, and network sockets on a live Linux host.
"""
from __future__ import annotations


import click
from rich.console import Console

from deepview.cli.formatters.table import TableRenderer
from deepview.inspect.file import FileInspector
from deepview.inspect.memory_peek import MemoryPeek
from deepview.inspect.net import NetInspector
from deepview.inspect.process import ProcessInspector


@click.group()
def inspect() -> None:
    """On-demand forensic inspection of live processes, files, and sockets."""


@inspect.command("process")
@click.option("--pid", type=int, required=True)
@click.pass_context
def inspect_process(ctx, pid):
    """Show status, maps, fds, namespaces, and sockets for *pid*."""
    console: Console = ctx.obj["console"]
    result = ProcessInspector(pid).to_plugin_result()
    TableRenderer().render(result)
    # Render the nested metadata blocks if present.
    md = result.metadata or {}
    if md.get("libraries"):
        console.print("\n[bold]Loaded libraries:[/bold]")
        for lib in md["libraries"]:
            console.print(f"  {lib}")
    if md.get("sockets_sample"):
        console.print("\n[bold]Open sockets:[/bold]")
        for s in md["sockets_sample"]:
            console.print(f"  {s['proto']} {s['local']} -> {s['remote']} ({s['state']})")


@inspect.command("file")
@click.argument("path", type=click.Path(exists=False))
@click.pass_context
def inspect_file(ctx, path):
    """Hash + magic + mount attribution for *path*."""
    result = FileInspector(path).to_plugin_result()
    TableRenderer().render(result)


@inspect.command("memory")
@click.option("--pid", type=int, required=True)
@click.option("--yara", "yara_rules", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--va", type=str, default=None, help="Virtual address (hex) to read")
@click.option("--length", type=int, default=256, show_default=True)
@click.pass_context
def inspect_memory(ctx, pid, yara_rules, va, length):
    """Peek process memory, optionally running a YARA scan or a VA read."""
    console: Console = ctx.obj["console"]
    peek = MemoryPeek(pid)
    try:
        if va is not None:
            va_int = int(va, 16) if va.startswith(("0x", "0X")) else int(va, 16)
            data = peek.read_range(va_int, length)
            console.print(f"[bold]{va_int:#x} .. {va_int + length:#x}[/bold]")
            console.print(data.hex())
            return
        if yara_rules:
            hits = list(peek.scan_yara(yara_rules))
            if not hits:
                console.print("[dim]no YARA matches[/dim]")
                return
            for h in hits:
                console.print(f"[green]{h.rule_name}[/green] at 0x{h.offset:x} ({h.metadata.get('pathname', '')})")
            return
        # Default: show the region map.
        console.print(f"[bold]Regions for pid {pid}:[/bold]")
        for region in peek.layer.regions:
            console.print(
                f"  0x{region.start:x}-0x{region.end:x} {region.perms} {region.pathname}"
            )
    finally:
        peek.close()


@inspect.command("net")
@click.option("--pid", type=int, default=None)
@click.pass_context
def inspect_net(ctx, pid):
    """Live TCP/UDP socket table (optionally filtered by pid)."""
    result = NetInspector(pid).to_plugin_result()
    TableRenderer().render(result)
