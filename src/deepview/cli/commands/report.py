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


def _detections_from_artifacts(context: object) -> list:
    """Reconstruct ``Detection`` objects from any 'name'-bearing artifact dicts.

    Detectors persist findings into the artifact store as plain dicts; the STIX
    and ATT&CK exporters consume ``Detection`` instances, so bridge the two here.
    """
    from deepview.core.types import EventSeverity
    from deepview.detection.anti_forensics import Detection

    detections: list[Detection] = []
    for items in context.artifacts.all_artifacts().values():  # type: ignore[attr-defined]
        for item in items:
            if not isinstance(item, dict) or "name" not in item:
                continue
            try:
                severity = EventSeverity(str(item.get("severity", "info")).lower())
            except ValueError:
                severity = EventSeverity.INFO
            evidence = item.get("evidence")
            detections.append(
                Detection(
                    name=str(item["name"]),
                    severity=severity,
                    description=str(item.get("description", "")),
                    offset=int(item.get("offset", 0) or 0),
                    pid=int(item.get("pid", 0) or 0),
                    process_name=str(item.get("process_name", "")),
                    technique=str(item.get("technique", "")),
                    evidence=evidence if isinstance(evidence, dict) else {},
                )
            )
    return detections


@report.command()
@click.option("--session", type=str, default=None, help="Session ID")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (JSON)")
@click.pass_context
def timeline(ctx, session, output):
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
        detections = _detections_from_artifacts(context)
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
