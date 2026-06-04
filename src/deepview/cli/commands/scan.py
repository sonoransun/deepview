"""``deepview scan`` — YARA / IoC scanning over files and directories.

Backends are imported lazily so the command group stays importable on a core
install; ``yara`` degrades to an install hint when ``yara-python`` is absent.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.table import Table


def _iter_files(target: Path) -> list[Path]:
    """Return the target itself (file) or every regular file beneath it (dir)."""
    if target.is_file():
        return [target]
    return sorted(p for p in target.rglob("*") if p.is_file())


@click.group()
def scan() -> None:
    """Pattern matching and IoC scanning."""


@scan.command()
@click.option("--target", "-t", type=click.Path(exists=True), required=True,
              help="File or directory to scan")
@click.option("--rules", "-r", type=click.Path(exists=True), required=True,
              help="YARA rules file or directory")
@click.pass_context
def yara(ctx: click.Context, target: str, rules: str) -> None:
    """Run YARA rules against a target file or directory."""
    console = ctx.obj["console"]
    from deepview.core.exceptions import RuleCompileError, ScanError
    from deepview.scanning.yara_engine import YaraScanner

    scanner = YaraScanner()
    if not scanner.is_available:
        console.print(
            "[yellow]yara-python is not installed. "
            "Install with: pip install 'deepview[memory]'[/yellow]"
        )
        raise click.Abort()
    try:
        scanner.load_rules(Path(rules))
    except (ScanError, RuleCompileError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.Abort() from exc

    files = _iter_files(Path(target))
    table = Table(title="YARA matches")
    table.add_column("File", style="cyan")
    table.add_column("Rule")
    table.add_column("Offset", justify="right")
    table.add_column("Tags")
    total = 0
    for f in files:
        try:
            for result in scanner.scan_file(f):
                total += 1
                tags = ",".join(result.metadata.get("tags", []))
                table.add_row(str(f), result.rule_name, f"{result.offset:#x}", tags)
        except ScanError as exc:
            console.print(f"[red]{f}: {exc}[/red]")

    if total:
        console.print(table)
    console.print(
        f"[green]{total} match(es)[/green] across {len(files)} file(s) "
        f"({scanner.rule_count} rule file(s))"
    )


@scan.command()
@click.option("--target", "-t", type=click.Path(exists=True), required=True,
              help="File or directory to scan")
@click.option("--ioc-file", type=click.Path(exists=True), required=True,
              help="IoC indicator JSON file")
@click.pass_context
def ioc(ctx: click.Context, target: str, ioc_file: str) -> None:
    """Match indicators of compromise against a target's bytes."""
    console = ctx.obj["console"]
    from deepview.scanning.indicators import IndicatorEngine

    engine = IndicatorEngine()
    try:
        engine.load_indicators(Path(ioc_file))
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        console.print(f"[red]failed to load indicators: {exc}[/red]")
        raise click.Abort() from exc

    table = Table(title="IoC matches")
    table.add_column("File", style="cyan")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Severity")
    table.add_column("Offset", justify="right")
    total = 0
    for f in _iter_files(Path(target)):
        try:
            data = f.read_bytes()
        except OSError as exc:
            console.print(f"[red]{f}: {exc}[/red]")
            continue
        for match in engine.scan_bytes(data):
            total += 1
            table.add_row(
                str(f),
                match.indicator.ioc_type,
                match.indicator.value,
                match.indicator.severity,
                f"{match.offset:#x}",
            )

    if total:
        console.print(table)
    console.print(
        f"[green]{total} indicator match(es)[/green] "
        f"({engine.indicator_count} indicator(s) loaded)"
    )


@scan.command()
@click.option("--list", "list_rules", is_flag=True, help="List available rule files")
@click.option("--update", is_flag=True, help="Update rule sets (manual today)")
@click.pass_context
def rules(ctx: click.Context, list_rules: bool, update: bool) -> None:
    """Inspect the configured YARA rules directory."""
    console = ctx.obj["console"]
    context = ctx.obj["context"]
    from deepview.scanning.rules.manager import RuleManager

    mgr = RuleManager(context.config)
    if update:
        console.print(
            "[yellow]Automatic rule update is not implemented; drop .yar/.yara "
            f"files into {mgr.rules_dir} manually.[/yellow]"
        )
        return

    names = mgr.list_rules()
    console.print(f"[bold]Rules directory:[/bold] {mgr.rules_dir}")
    table = Table(title="YARA rules", min_width=20)
    table.add_column("Name", style="cyan")
    for name in names:
        table.add_row(name)
    console.print(table)
    if not names:
        console.print("[dim]No rule files found.[/dim]")
