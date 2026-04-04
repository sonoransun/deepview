from __future__ import annotations
import click
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

@click.group()
def memory():
    """Memory forensics operations."""
    pass

@memory.command()
@click.option("--method", type=click.Choice(["lime", "avml", "winpmem", "osxpmem", "auto"]), default="auto", help="Acquisition method")
@click.option("--format", "fmt", type=click.Choice(["raw", "lime", "padded"]), default="raw", help="Output format")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output file path")
@click.option("--compress", is_flag=True, help="Compress output")
@click.pass_context
def acquire(ctx, method, fmt, output, compress):
    """Acquire memory from live system."""
    console = ctx.obj["console"]
    context = ctx.obj["context"]
    console.print(f"[bold]Acquiring memory...[/bold]")
    console.print(f"  Method: {method}")
    console.print(f"  Format: {fmt}")
    console.print(f"  Output: {output}")
    console.print("[yellow]Acquisition requires platform-specific tools. Run 'deepview doctor' to check available providers.[/yellow]")

@memory.command()
@click.option("--image", "-i", type=click.Path(exists=True), required=True, help="Memory image path")
@click.option("--plugin", "-p", type=str, required=True, help="Analysis plugin to run")
@click.option("--engine", type=click.Choice(["volatility", "memprocfs", "auto"]), default="auto", help="Analysis engine")
@click.option("--pid", type=int, default=None, help="Filter by PID")
@click.pass_context
def analyze(ctx, image, plugin, engine, pid):
    """Analyze a memory image."""
    console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    console.print(f"[bold]Analyzing memory image: {image}[/bold]")
    console.print(f"  Engine: {engine}")
    console.print(f"  Plugin: {plugin}")
    if pid:
        console.print(f"  PID filter: {pid}")

    try:
        from deepview.memory.manager import MemoryManager

        mem_manager = MemoryManager(context)
        image_path = Path(image)

        # Open image as a data layer and register it
        layer = mem_manager.open_layer(image_path)
        context.layers.register(image_path.stem, layer)

        # Build plugin config from CLI options
        plugin_config = {
            "image_path": str(image_path),
            "engine": engine,
        }
        if pid is not None:
            plugin_config["pid"] = pid

        # Instantiate and run the requested plugin
        plugin_instance = context.plugins.instantiate(plugin, config=plugin_config)
        result = plugin_instance.run()

        # Display results as a Rich table
        from rich.table import Table

        table = Table(
            title=f"Plugin: {plugin}",
            show_lines=True,
        )
        for col in result.columns:
            table.add_column(col, style="cyan")

        for row in result.rows:
            table.add_row(*(str(row.get(col, "")) for col in result.columns))

        console.print(table)

        if result.metadata:
            console.print(f"\n[dim]Metadata: {result.metadata}[/dim]")

        console.print(f"\n[green]Analysis complete. {len(result.rows)} rows returned.[/green]")

    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        raise SystemExit(1)

@memory.command()
@click.option("--generate", is_flag=True, help="Generate from DWARF/kernel")
@click.option("--download", is_flag=True, help="Download from symbol server")
@click.option("--list", "list_symbols", is_flag=True, help="List available symbols")
@click.pass_context
def symbols(ctx, generate, download, list_symbols):
    """Manage symbol tables."""
    console = ctx.obj["console"]
    if list_symbols:
        console.print("[bold]Available symbol tables:[/bold]")
        console.print("[dim]  No symbols cached yet.[/dim]")
    elif download:
        console.print("[bold]Downloading symbols...[/bold]")
        console.print("[yellow]Symbol download not yet implemented.[/yellow]")
    elif generate:
        console.print("[bold]Generating symbols...[/bold]")
        console.print("[yellow]Symbol generation not yet implemented.[/yellow]")

@memory.command("scan")
@click.option("--image", "-i", type=click.Path(exists=True), required=True, help="Memory image path")
@click.option("--rules", "-r", type=click.Path(exists=True), required=True, help="YARA rules file or directory")
@click.option("--rule-tag", type=str, default=None, help="Filter rules by tag")
@click.pass_context
def memory_scan(ctx, image, rules, rule_tag):
    """YARA scan on memory image."""
    console = ctx.obj["console"]
    console.print(f"[bold]Scanning memory image: {image}[/bold]")
    console.print(f"  Rules: {rules}")
    console.print("[yellow]Scanning requires YARA. Install with: pip install deepview[memory][/yellow]")
