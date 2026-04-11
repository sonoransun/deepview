from __future__ import annotations
import click
from rich.console import Console

from deepview.core.config import DeepViewConfig
from deepview.core.context import AnalysisContext
from deepview.core.logging import setup_logging

console = Console()

@click.group()
@click.option("--config", "config_path", type=click.Path(exists=False), default=None, help="Configuration file path")
@click.option("--output-format", "output_format", type=click.Choice(["json", "table", "csv", "timeline"]), default="table", help="Output format")
@click.option("--log-level", type=click.Choice(["debug", "info", "warning", "error"]), default="info", help="Logging level")
@click.option("--plugin-path", multiple=True, help="Additional plugin search paths")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output")
@click.version_option(package_name="deepview")
@click.pass_context
def main(ctx, config_path, output_format, log_level, plugin_path, no_color):
    """Deep View - Cross-platform computer system forensics toolkit."""
    ctx.ensure_object(dict)

    setup_logging(log_level)

    config = DeepViewConfig.load(config_path)
    if output_format:
        config.output_format = output_format
    if plugin_path:
        config.plugin_paths = list(plugin_path) + config.plugin_paths

    context = AnalysisContext(config=config)
    ctx.obj["context"] = context
    ctx.obj["console"] = Console(no_color=no_color)
    ctx.obj["output_format"] = output_format

# Import and register command groups
from deepview.cli.commands.memory import memory
from deepview.cli.commands.vm import vm
from deepview.cli.commands.trace import trace
from deepview.cli.commands.instrument import instrument
from deepview.cli.commands.scan import scan
from deepview.cli.commands.report import report
from deepview.cli.commands.disassemble import disassemble
from deepview.cli.commands.replay import replay
from deepview.cli.commands.inspect import inspect
from deepview.cli.commands.monitor import monitor
from deepview.cli.commands.dashboard import dashboard
from deepview.cli.commands.netmangle import netmangle

main.add_command(memory)
main.add_command(vm)
main.add_command(trace)
main.add_command(instrument)
main.add_command(scan)
main.add_command(report)
main.add_command(disassemble)
main.add_command(replay)
main.add_command(inspect)
main.add_command(monitor)
main.add_command(dashboard)
main.add_command(netmangle)

# Add plugin list command at root level
@main.command("plugins")
@click.option("--category", default=None, help="Filter by category")
@click.pass_context
def list_plugins(ctx, category):
    """List installed plugins."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    from deepview.core.types import PluginCategory
    cat = None
    if category:
        try:
            cat = PluginCategory(category)
        except ValueError:
            console.print(f"[red]Unknown category: {category}[/red]")
            return
    plugins = context.plugins.list_plugins(cat)
    if not plugins:
        console.print("[dim]No plugins found.[/dim]")
        return
    from rich.table import Table
    table = Table(title="Installed Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Category", style="green")
    table.add_column("Description")
    for p in plugins:
        table.add_row(p.name, p.version, p.category.value, p.description)
    console.print(table)

# Doctor command
@main.command("doctor")
@click.pass_context
def doctor(ctx):
    """Check system capabilities and available tools."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    from rich.table import Table

    console.print(f"\n[bold]Platform:[/bold] {context.platform.os.value}")
    console.print(f"[bold]Architecture:[/bold] {context.platform.arch}")
    console.print(f"[bold]Kernel:[/bold] {context.platform.kernel_version}")

    console.print(f"\n[bold]Capabilities:[/bold]")
    if context.platform.capabilities:
        for cap in sorted(context.platform.capabilities):
            console.print(f"  [green]✓[/green] {cap}")
    else:
        console.print("  [dim]None detected[/dim]")

    # Check optional tools
    import shutil
    tools = {
        "volatility3": "vol",
        "frida": "frida",
        "yara": "yara",
        "lief": None,  # Python only
        "dtrace": "dtrace",
        "vboxmanage": "vboxmanage",
        "vmrun": "vmrun",
        "virsh": "virsh",
    }

    console.print(f"\n[bold]External Tools:[/bold]")
    for name, cmd in tools.items():
        if cmd is None:
            try:
                __import__(name)
                console.print(f"  [green]✓[/green] {name} (Python library)")
            except ImportError:
                console.print(f"  [red]✗[/red] {name} (not installed)")
        else:
            if shutil.which(cmd):
                console.print(f"  [green]✓[/green] {name}")
            else:
                console.print(f"  [red]✗[/red] {name}")
