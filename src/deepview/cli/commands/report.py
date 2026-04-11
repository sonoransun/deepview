from __future__ import annotations
import click
from pathlib import Path

@click.group()
def report():
    """Generate forensic reports."""
    pass

@report.command()
@click.option("--session", type=str, default=None, help="Session ID")
@click.option("--template", type=click.Choice(["html", "markdown"]), default="html")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file")
@click.pass_context
def generate(ctx, session, template, output):
    """Create report from analysis session."""
    console = ctx.obj["console"]
    context = ctx.obj["context"]

    console.print(f"[bold]Generating {template} report...[/bold]")

    try:
        from deepview.reporting.engine import ReportEngine

        engine = ReportEngine(context)
        output_path = Path(output) if output else None

        if template == "html":
            content = engine.generate_html(output=output_path)
        else:
            content = engine.generate_markdown(output=output_path)

        if output_path:
            console.print(
                f"[green]Report written to: {output_path}[/green]"
            )
        else:
            console.print(content)

        console.print(f"[green]Report generation complete ({template}).[/green]")

    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise SystemExit(1)

@report.command()
@click.option(
    "--filesystem",
    "fs_paths",
    multiple=True,
    type=click.Path(exists=False),
    help="File paths to MACB-harvest (repeatable)",
)
@click.option("--auditd", "auditd_log", default="", help="Path to an auditd log file")
@click.option("--journald", is_flag=True, default=False, help="Include journald output")
@click.option(
    "--evtx",
    "evtx_files",
    multiple=True,
    type=click.Path(exists=False),
    help="Windows EVTX files to ingest (repeatable)",
)
@click.option("--unified-log", is_flag=True, default=False, help="Include macOS unified log")
@click.option(
    "--plaso-csv",
    "plaso_csv",
    type=click.Path(),
    default=None,
    help="Write a plaso-compatible CSV to this path",
)
@click.option(
    "--output",
    "-o",
    "output",
    type=click.Path(),
    default=None,
    help="JSON output file (default: print to stdout)",
)
@click.option("--host-id", default="localhost", help="Host identifier")
@click.pass_context
def timeline(
    ctx,
    fs_paths,
    auditd_log,
    journald,
    evtx_files,
    unified_log,
    plaso_csv,
    output,
    host_id,
):
    """Merge multiple forensic sources into a unified timeline."""
    from pathlib import Path as _Path
    import json as _json

    from rich.table import Table

    from deepview.reporting.timeline import TimelineMerger, write_plaso_csv
    from deepview.reporting.timeline.sources import (
        AuditdSource,
        EvtxSource,
        FilesystemSource,
        JournaldSource,
        MemoryArtifactSource,
        UnifiedLogSource,
    )

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    merger = TimelineMerger()
    if fs_paths:
        merger.add_source(
            FilesystemSource([_Path(p) for p in fs_paths], host_id=host_id)
        )
    if auditd_log:
        merger.add_source(AuditdSource([_Path(auditd_log)], host_id=host_id))
    if journald:
        merger.add_source(JournaldSource(host_id=host_id))
    if evtx_files:
        merger.add_source(
            EvtxSource([_Path(p) for p in evtx_files], host_id=host_id)
        )
    if unified_log:
        merger.add_source(UnifiedLogSource(host_id=host_id))
    merger.add_source(
        MemoryArtifactSource(context.artifacts.all_artifacts(), host_id=host_id)
    )
    events = merger.build()
    if output:
        _Path(output).write_text(
            _json.dumps([e.model_dump(mode="json") for e in events], indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]Wrote {len(events)} events to {output}[/green]")
    else:
        table = Table(title=f"Unified timeline ({len(events)} events)")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Source")
        table.add_column("Severity")
        table.add_column("Description")
        table.add_column("MITRE")
        for e in events[:500]:
            table.add_row(
                e.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S"),
                e.source.value,
                e.severity.value,
                e.description[:80],
                ",".join(e.mitre_techniques),
            )
        console.print(table)
    if plaso_csv:
        written = write_plaso_csv(events, _Path(plaso_csv))
        console.print(f"[green]Wrote {written} rows to plaso CSV: {plaso_csv}[/green]")

@report.command()
@click.option("--session", type=str, default=None, help="Session ID")
@click.option("--format", "fmt", type=click.Choice(["stix", "attck", "json"]), default="stix")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file")
@click.pass_context
def export(ctx, session, fmt, output):
    """Export to STIX/ATT&CK format."""
    console = ctx.obj["console"]
    console.print(f"[bold]Exporting in {fmt} format...[/bold]")
    console.print("[yellow]Export not yet connected to backend.[/yellow]")
