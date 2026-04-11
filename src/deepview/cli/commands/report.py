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
@click.option("--session", type=str, default=None, help="Session ID")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file")
@click.pass_context
def timeline(ctx, session, output):
    """Generate event timeline."""
    console = ctx.obj["console"]
    console.print("[yellow]Timeline generation not yet connected to backend.[/yellow]")

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
