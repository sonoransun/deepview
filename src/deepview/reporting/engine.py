"""Report generation engine."""
from __future__ import annotations
import html as html_mod
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("reporting.engine")


class ReportEngine:
    """Generate forensic analysis reports."""

    def __init__(self, context: AnalysisContext):
        self._context = context
        self._template_dir = Path(__file__).parent / "templates"

    def generate_json(self, output: Path | None = None) -> dict:
        """Generate a JSON report from the current session."""
        report = {
            "report_type": "deep_view_forensic_report",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_id": self._context.session_id,
            "platform": {
                "os": self._context.platform.os.value,
                "arch": self._context.platform.arch,
                "kernel": self._context.platform.kernel_version,
            },
            "artifacts": self._context.artifacts.all_artifacts(),
            "layers": self._context.layers.list_layers(),
        }

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, default=str))
            log.info("report_generated", format="json", output=str(output))

        return report

    def generate_markdown(self, output: Path | None = None) -> str:
        """Generate a Markdown report."""
        report = self.generate_json()

        lines = [
            f"# Deep View Forensic Report",
            f"",
            f"**Generated:** {report['generated_at']}",
            f"**Session:** {report['session_id']}",
            f"",
            f"## Platform",
            f"- **OS:** {report['platform']['os']}",
            f"- **Architecture:** {report['platform']['arch']}",
            f"- **Kernel:** {report['platform']['kernel']}",
            f"",
        ]

        # Artifacts
        artifacts = report.get("artifacts", {})
        if artifacts:
            lines.append("## Artifacts")
            lines.append("")
            for category, items in artifacts.items():
                lines.append(f"### {category.title()}")
                lines.append("")
                for item in items:
                    lines.append(f"- {json.dumps(item, default=str)}")
                lines.append("")

        # Layers
        layers = report.get("layers", [])
        if layers:
            lines.append("## Data Layers")
            lines.append("")
            for layer in layers:
                lines.append(f"- {layer}")
            lines.append("")

        text = "\n".join(lines)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text)
            log.info("report_generated", format="markdown", output=str(output))

        return text

    def generate_html(self, output: Path | None = None) -> str:
        """Generate an HTML report."""
        report = self.generate_json()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Deep View Forensic Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        h3 {{ color: #0f3460; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #16213e; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-warning {{ color: #ffc107; font-weight: bold; }}
        .severity-info {{ color: #17a2b8; }}
        .meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Deep View Forensic Report</h1>
        <p class="meta">Generated: {html_mod.escape(str(report['generated_at']))} | Session: {html_mod.escape(str(report['session_id']))}</p>

        <h2>Platform</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>OS</td><td>{html_mod.escape(str(report['platform']['os']))}</td></tr>
            <tr><td>Architecture</td><td>{html_mod.escape(str(report['platform']['arch']))}</td></tr>
            <tr><td>Kernel</td><td>{html_mod.escape(str(report['platform']['kernel']))}</td></tr>
        </table>
"""

        artifacts = report.get("artifacts", {})
        if artifacts:
            html += "        <h2>Artifacts</h2>\n"
            for category, items in artifacts.items():
                html += f"        <h3>{html_mod.escape(category.title())}</h3>\n"
                if items:
                    keys = list(items[0].keys()) if items else []
                    html += "        <table>\n"
                    html += "            <tr>" + "".join(f"<th>{html_mod.escape(str(k))}</th>" for k in keys) + "</tr>\n"
                    for item in items:
                        html += "            <tr>" + "".join(f"<td>{html_mod.escape(str(item.get(k, '')))}</td>" for k in keys) + "</tr>\n"
                    html += "        </table>\n"

        html += """    </div>
</body>
</html>"""

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(html)
            log.info("report_generated", format="html", output=str(output))

        return html
