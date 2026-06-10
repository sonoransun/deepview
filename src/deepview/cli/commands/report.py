from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path

import click

@click.group()
def report():
    """Generate forensic reports."""
    pass

@report.command()
@click.option("--session", type=str, default=None, help="Session ID")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "markdown", "json"]),
    default="html",
    help="Report format",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file")
@click.pass_context
def generate(ctx, session, fmt, output):
    """Create a forensic report (visual HTML, Markdown, or JSON)."""
    import json

    console = ctx.obj["console"]
    context = ctx.obj["context"]

    console.print(f"[bold]Generating {fmt} report...[/bold]")

    try:
        from deepview.reporting.engine import ReportEngine

        engine = ReportEngine(context)
        output_path = Path(output) if output else None

        if fmt == "html":
            content = engine.generate_html(output=output_path)
        elif fmt == "markdown":
            content = engine.generate_markdown(output=output_path)
        else:  # json
            report = engine.generate_json(output=output_path)
            content = json.dumps(report, indent=2, default=str)

        if output_path:
            console.print(f"[green]Report written to: {output_path}[/green]")
        else:
            console.print(content)

        console.print(f"[green]Report generation complete ({fmt}).[/green]")

    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise SystemExit(1)

def _parse_timestamp(raw: object) -> datetime | None:
    """Best-effort parse of an artifact ``timestamp`` (ISO string or epoch)."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError:
        return None


def _render_swimlane(console, builder) -> None:
    """Print an ASCII swimlane (lanes by severity) for a TimelineBuilder."""
    from rich.table import Table
    from rich.text import Text

    width = 48
    blocks = " ▁▂▃▄▅▆▇█"
    severity_style = {"critical": "bold red", "warning": "yellow", "info": "cyan"}
    span = builder.span()
    if span is None:
        console.print("[dim](no timestamped entries to plot)[/dim]")
        return
    t0, t1 = span
    total = (t1 - t0).total_seconds() or 1.0
    lanes = builder.lanes(by="severity")
    grid = Table.grid(padding=(0, 1))
    grid.add_column(justify="right", min_width=10)
    grid.add_column()
    for lane in ("critical", "warning", "info"):
        entries = lanes.get(lane)
        if not entries:
            continue
        counts = [0] * width
        for e in entries:
            frac = (e.timestamp - t0).total_seconds() / total
            counts[min(width - 1, int(frac * (width - 1)))] += 1
        vmax = max(counts) or 1
        bar = "".join(blocks[min(len(blocks) - 1, int(c / vmax * (len(blocks) - 1)))] for c in counts)
        grid.add_row(lane, Text(bar, style=severity_style.get(lane, "white")))
    console.print(grid)


@report.command()
@click.option("--session", type=str, default=None, help="Session ID")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (JSON)")
@click.option("--visual", is_flag=True, default=False, help="Render an ASCII swimlane")
@click.pass_context
def timeline(ctx, session, output, visual):
    """Build an event timeline from timestamped artifacts."""
    import json

    from rich.table import Table

    from deepview.reporting.timeline import TimelineBuilder, TimelineEntry

    console = ctx.obj["console"]
    context = ctx.obj["context"]

    builder = TimelineBuilder()
    for category, items in context.artifacts.all_artifacts().items():
        for item in items:
            if not isinstance(item, dict):
                continue
            ts = _parse_timestamp(item.get("timestamp"))
            if ts is None:
                continue
            builder.add_entry(
                TimelineEntry(
                    timestamp=ts,
                    event_type=str(item.get("event_type", category)),
                    description=str(item.get("description", item.get("name", ""))),
                    source=str(item.get("source", category)),
                    severity=str(item.get("severity", "info")),
                    pid=int(item.get("pid", 0) or 0),
                )
            )

    if output:
        Path(output).write_text(json.dumps(builder.to_dict_list(), indent=2))
        console.print(
            f"[green]Timeline ({builder.entry_count} entries) written to {output}[/green]"
        )
        return

    if visual:
        _render_swimlane(console, builder)

    table = Table(title="Event timeline", min_width=40)
    table.add_column("Timestamp", style="cyan")
    table.add_column("Source")
    table.add_column("Severity")
    table.add_column("Description")
    for entry in builder.build():
        table.add_row(entry.timestamp.isoformat(), entry.source, entry.severity, entry.description)
    console.print(table)
    console.print(f"[green]{builder.entry_count} timeline entr(ies).[/green]")


@report.command()
@click.option("--session", type=str, default=None, help="Session ID")
@click.option("--format", "fmt", type=click.Choice(["stix", "attck", "json"]), default="stix")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file")
@click.pass_context
def export(ctx, session, fmt, output):
    """Export findings as a STIX 2.1 bundle, ATT&CK Navigator layer, or JSON."""
    import json

    console = ctx.obj["console"]
    context = ctx.obj["context"]

    if fmt == "json":
        from deepview.reporting.engine import ReportEngine

        payload: object = ReportEngine(context).generate_json()
    else:
        from deepview.reporting.engine import iter_detections

        detections = iter_detections(context)
        if fmt == "stix":
            from deepview.reporting.export import STIXExporter

            payload = STIXExporter().export_detections(detections)
        else:  # attck
            from deepview.reporting.export import ATTCKMapper

            payload = ATTCKMapper().generate_navigator_layer(detections)
        console.print(f"[dim]{len(detections)} detection artifact(s) considered[/dim]")

    text = json.dumps(payload, indent=2, default=str)
    if output:
        Path(output).write_text(text)
        console.print(f"[green]{fmt} export written to {output}[/green]")
    else:
        console.print(text)
