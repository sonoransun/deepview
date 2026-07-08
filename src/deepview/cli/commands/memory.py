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
    context: AnalysisContext = ctx.obj["context"]
    console.print("[bold]Acquiring memory...[/bold]")
    console.print(f"  Method: {method}")
    console.print(f"  Format: {fmt}")
    console.print(f"  Output: {output}")

    try:
        from deepview.memory.manager import MemoryManager
        from deepview.core.types import AcquisitionTarget, DumpFormat

        mem_manager = MemoryManager(context)
        if not mem_manager.available_providers:
            console.print(
                "[yellow]No acquisition provider available on this platform. "
                "Run 'deepview doctor' to check.[/yellow]"
            )
            raise SystemExit(1)

        fmt_map = {
            "raw": DumpFormat.RAW,
            "lime": DumpFormat.LIME,
            "padded": DumpFormat.PADDED,
        }
        result = mem_manager.acquire(
            target=AcquisitionTarget(),
            output=Path(output),
            method=method,
            fmt=fmt_map.get(fmt, DumpFormat.RAW),
        )

        if not result.success:
            console.print("[red]Acquisition failed.[/red]")
            raise SystemExit(1)

        console.print(
            f"[green]Acquired {result.size_bytes:,} bytes in "
            f"{result.duration_seconds:.1f}s[/green]"
        )
        console.print(f"  Output:  {result.output_path}")
        console.print(f"  {result.algorithm.upper()}: {result.hash_sha256}")
        if result.manifest_path:
            console.print(f"  Manifest: {result.manifest_path}")
        if result.truncated:
            console.print(
                f"[yellow]WARNING: acquisition was truncated and the image is "
                f"INCOMPLETE ({result.read_error}). Do not certify it as a full "
                f"capture.[/yellow]"
            )

        from deepview.utils.audit import audit_event, default_audit_log

        audit_event(
            default_audit_log(context.config.config_dir),
            "memory.acquire",
            method=method,
            output=str(result.output_path),
            algorithm=result.algorithm,
            digest=result.hash_sha256,
            size_bytes=result.size_bytes,
            truncated=result.truncated,
        )
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]Error during acquisition: {e}[/red]")
        raise SystemExit(1)

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
    context: AnalysisContext = ctx.obj["context"]
    console.print(f"[bold]Scanning memory image: {image}[/bold]")
    console.print(f"  Rules: {rules}")

    from deepview.scanning.yara_engine import YaraScanner

    scanner = YaraScanner()
    if not scanner.is_available:
        console.print(
            "[yellow]yara-python not installed. Install with: "
            "pip install deepview[memory][/yellow]"
        )
        raise SystemExit(1)

    try:
        from deepview.memory.manager import MemoryManager

        scanner.load_rules(Path(rules))
        mem_manager = MemoryManager(context)
        layer = mem_manager.open_layer(Path(image))
        results = list(scanner.scan_layer(layer))
    except Exception as e:
        console.print(f"[red]Scan error: {e}[/red]")
        raise SystemExit(1)

    from rich.table import Table

    table = Table(title=f"YARA matches ({len(results)})")
    table.add_column("Offset", style="cyan")
    table.add_column("Rule")
    table.add_column("String")
    for r in results[:1000]:
        table.add_row(hex(r.offset), r.rule_name, str(r.metadata.get("string_id", "")))
    console.print(table)
    console.print(f"[green]{len(results)} match(es).[/green]")

@memory.command()
@click.option("--image", "-i", type=click.Path(exists=True), required=True, help="Memory image path")
@click.option("--sha256", "expected", default=None, help="Expected digest to verify against")
@click.option("--manifest", type=click.Path(exists=True), default=None, help="Manifest with recorded digest")
@click.pass_context
def verify(ctx, image, expected, manifest):
    """Verify a memory image's integrity against a hash or evidence manifest."""
    import json

    console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]

    from deepview.utils.hashing import hash_file, verify_hash

    algorithm = "sha256"
    if manifest and not expected:
        try:
            data = json.loads(Path(manifest).read_text())
            artifacts = data.get("artifacts", [])
        except (OSError, ValueError) as e:
            console.print(f"[red]Cannot read manifest: {e}[/red]")
            raise SystemExit(2)
        image_name = Path(image).name
        match = next(
            (a for a in artifacts if Path(a.get("path", "")).name == image_name),
            artifacts[0] if artifacts else None,
        )
        if match:
            expected = match.get("digest")
            algorithm = match.get("algorithm", "sha256")

    if not expected:
        console.print("[red]Provide --sha256 <digest> or --manifest with a recorded digest.[/red]")
        raise SystemExit(2)

    try:
        matched = verify_hash(Path(image), expected, algorithm)
        computed = hash_file(Path(image), algorithm)
    except Exception as e:
        console.print(f"[red]Verification error: {e}[/red]")
        raise SystemExit(2)

    from deepview.utils.audit import audit_event, default_audit_log

    audit_event(
        default_audit_log(context.config.config_dir),
        "memory.verify",
        image=str(image),
        algorithm=algorithm,
        expected=expected,
        computed=computed,
        matched=matched,
    )

    if matched:
        console.print(f"[green]OK: {image} matches the expected {algorithm} digest.[/green]")
    else:
        console.print(f"[red]MISMATCH: {image} does NOT match the expected {algorithm} digest.[/red]")
        console.print(f"  expected: {expected}")
        console.print(f"  computed: {computed}")
        raise SystemExit(1)
