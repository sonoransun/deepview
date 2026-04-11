"""``deepview persistence`` CLI group."""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table


@click.group()
def persistence() -> None:
    """Persistence detection commands."""


@persistence.command("scan")
@click.option("--root", default="/", help="Root filesystem to scan (for offline images)")
@click.option(
    "--manifest-roots",
    default="",
    help="Comma-separated K8s manifest directories to scan",
)
@click.option(
    "--no-user-scope",
    "no_user_scope",
    is_flag=True,
    default=False,
    help="Skip user home directory scanning",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=False),
    default=None,
    help="Path to a JSON file containing baseline fingerprints",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write results as JSON to this file",
)
@click.pass_context
def scan(
    ctx: click.Context,
    root: str,
    manifest_roots: str,
    no_user_scope: bool,
    baseline_path: str | None,
    output_path: str | None,
) -> None:
    """Scan the host for persistence artifacts."""
    from deepview.core.context import AnalysisContext
    from deepview.detection.persistence.manager import PersistenceManager

    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    manifest_list = [p for p in manifest_roots.split(",") if p]
    baseline_fps: set[str] | None = None
    if baseline_path and Path(baseline_path).is_file():
        try:
            baseline_fps = set(json.loads(Path(baseline_path).read_text(encoding="utf-8")))
        except Exception:
            console.print(f"[yellow]Could not parse baseline file {baseline_path}[/yellow]")

    mgr = PersistenceManager(
        context,
        linux_root=root,
        macos_root=root,
        manifest_roots=manifest_list or None,
    )
    findings = mgr.scan(
        include_user_scope=not no_user_scope,
        baseline_fingerprints=baseline_fps,
    )
    table = Table(title=f"Persistence findings ({len(findings)})")
    table.add_column("Mechanism", style="cyan")
    table.add_column("Location")
    table.add_column("MITRE")
    table.add_column("Severity")
    table.add_column("Reasons")
    table.add_column("Baseline Δ", justify="center")
    for f in findings:
        table.add_row(
            f.mechanism,
            f.location[:80],
            f.mitre_technique,
            f.severity.value,
            ", ".join(f.suspicious_reasons)[:60],
            "✓" if f.deviation_from_baseline else "",
        )
    console.print(table)

    if output_path:
        as_dicts = [f.model_dump(mode="json") for f in findings]
        Path(output_path).write_text(json.dumps(as_dicts, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote {len(findings)} findings to {output_path}[/green]")


@persistence.command("baseline")
@click.option("--root", default="/", help="Root filesystem to scan")
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    required=True,
    help="Where to write the baseline fingerprint list",
)
@click.pass_context
def capture_baseline(ctx: click.Context, root: str, output_path: str) -> None:
    """Capture the current persistence state as a baseline fingerprint list."""
    from deepview.core.context import AnalysisContext
    from deepview.detection.persistence.manager import PersistenceManager

    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    mgr = PersistenceManager(context, linux_root=root, macos_root=root)
    findings = mgr.scan(feed_correlation=False)
    fps = sorted({f.fingerprint() for f in findings})
    Path(output_path).write_text(json.dumps(fps, indent=2), encoding="utf-8")
    console.print(
        f"[green]Captured baseline with {len(fps)} fingerprints -> {output_path}[/green]"
    )
