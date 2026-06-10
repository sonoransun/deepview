"""Report generation engine."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from deepview.core.findings import Finding, coerce_severity, severity_rank
from deepview.core.logging import get_logger
from deepview.core.types import EventSeverity

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.detection.anti_forensics import Detection
    from deepview.reporting.timeline import TimelineBuilder

log = get_logger("reporting.engine")


def iter_findings(context: AnalysisContext) -> list[Finding]:
    """Reconstruct :class:`Finding`s from every ``name``-bearing artifact."""
    findings: list[Finding] = []
    for items in context.artifacts.all_artifacts().values():
        for item in items:
            if isinstance(item, dict) and "name" in item:
                findings.append(Finding.from_artifact(item))
    return findings


def iter_detections(context: AnalysisContext) -> list[Detection]:
    """Bridge ``name``-bearing artifacts to ``Detection`` objects for export."""
    from deepview.detection.anti_forensics import Detection

    detections: list[Detection] = []
    for items in context.artifacts.all_artifacts().values():
        for item in items:
            if not isinstance(item, dict) or "name" not in item:
                continue
            evidence = item.get("evidence")
            detections.append(
                Detection(
                    name=str(item["name"]),
                    severity=coerce_severity(item.get("severity", "info")),
                    description=str(item.get("description", "")),
                    offset=int(item.get("offset", 0) or 0),
                    pid=int(item.get("pid", 0) or 0),
                    process_name=str(item.get("process_name", "")),
                    technique=str(item.get("technique", "")),
                    evidence=evidence if isinstance(evidence, dict) else {},
                )
            )
    return detections


def summarize_findings(findings: list[Finding]) -> dict[str, Any]:
    """Roll findings up into the severity/technique/process shape reports use."""
    by_severity = {"critical": 0, "warning": 0, "info": 0}
    techniques: dict[str, int] = {}
    processes: dict[int, dict[str, Any]] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        for tid in f.attack_ids:
            techniques[tid] = techniques.get(tid, 0) + 1
        if f.pid:
            entry = processes.setdefault(
                f.pid,
                {"pid": f.pid, "name": f.process_name, "severity": "info", "count": 0},
            )
            entry["count"] += 1
            if f.process_name and not entry["name"]:
                entry["name"] = f.process_name
            if severity_rank(f.severity) > severity_rank(coerce_severity(entry["severity"])):
                entry["severity"] = f.severity.value
    top_techniques = sorted(techniques.items(), key=lambda kv: kv[1], reverse=True)[:10]
    affected = sorted(
        processes.values(),
        key=lambda p: (severity_rank(coerce_severity(p["severity"])), p["count"]),
        reverse=True,
    )
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "top_techniques": top_techniques,
        "affected_processes": affected,
    }


class ReportEngine:
    """Generate forensic analysis reports."""

    def __init__(self, context: AnalysisContext):
        self._context = context
        self._template_dir = Path(__file__).parent / "templates"

    def _base(self) -> dict[str, Any]:
        return {
            "report_type": "deep_view_forensic_report",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_id": self._context.session_id,
            "platform": {
                "os": self._context.platform.os.value,
                "arch": self._context.platform.arch,
                "kernel": self._context.platform.kernel_version,
            },
        }

    def generate_json(self, output: Path | None = None) -> dict:
        """Generate a JSON report from the current session."""
        findings = iter_findings(self._context)
        report = self._base()
        report["summary"] = summarize_findings(findings)
        report["findings"] = [f.to_artifact() for f in findings]
        report["artifacts"] = self._context.artifacts.all_artifacts()
        report["layers"] = self._context.layers.list_layers()

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, default=str))
            log.info("report_generated", format="json", output=str(output))

        return report

    def generate_markdown(self, output: Path | None = None) -> str:
        """Generate a Markdown report with a findings roll-up."""
        report = self.generate_json()
        summary = report["summary"]

        lines = [
            "# Deep View Forensic Report",
            "",
            f"**Generated:** {report['generated_at']}",
            f"**Session:** {report['session_id']}",
            "",
            "## Summary",
            "",
            f"- **Total findings:** {summary['total']}",
            f"- **Critical:** {summary['by_severity']['critical']}",
            f"- **Warning:** {summary['by_severity']['warning']}",
            f"- **Info:** {summary['by_severity']['info']}",
            "",
            "## Platform",
            f"- **OS:** {report['platform']['os']}",
            f"- **Architecture:** {report['platform']['arch']}",
            f"- **Kernel:** {report['platform']['kernel']}",
            "",
        ]

        if summary["top_techniques"]:
            lines += ["## Top Techniques", ""]
            for tid, count in summary["top_techniques"]:
                lines.append(f"- {tid}: {count}")
            lines.append("")

        if report["findings"]:
            lines += ["## Findings", ""]
            for f in report["findings"]:
                lines.append(
                    f"- **[{f['severity']}]** {f['title']} "
                    f"({f.get('technique') or 'n/a'}, pid={f['pid']}): {f['description']}"
                )
            lines.append("")

        layers = report.get("layers", [])
        if layers:
            lines += ["## Data Layers", ""]
            lines += [f"- {layer}" for layer in layers]
            lines.append("")

        text = "\n".join(lines)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text)
            log.info("report_generated", format="markdown", output=str(output))
        return text

    def generate_html(self, output: Path | None = None) -> str:
        """Generate a visual HTML report (timeline, ATT&CK heatmap, tree)."""
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        from deepview.reporting import visuals
        from deepview.reporting.export import ATTCKMapper

        findings = iter_findings(self._context)
        summary = summarize_findings(findings)
        timeline = self._build_timeline(findings)
        tree = self._build_process_tree()
        coverage = ATTCKMapper().coverage(iter_detections(self._context))

        buckets = timeline.bucketed(1.0)
        rate_series = [c for _, c in buckets]
        rate_svg = visuals.rate_chart_svg(rate_series) if len(rate_series) >= 2 else ""

        ctx = self._base()
        ctx.update(
            {
                "summary": summary,
                "findings": [f.to_artifact() for f in findings],
                "layers": self._context.layers.list_layers(),
                "severity_chart_svg": visuals.severity_chart_svg(summary["by_severity"]),
                "rate_chart_svg": rate_svg,
                "timeline_svg": visuals.timeline_svg(timeline.lanes(by="severity")),
                "attack_matrix_svg": visuals.attack_matrix_svg(coverage),
                "process_tree_svg": visuals.process_tree_svg(tree),
            }
        )

        env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        html = env.get_template("report.html.j2").render(**ctx)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(html)
            log.info("report_generated", format="html", output=str(output))
        return html

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def _build_timeline(self, findings: list[Finding]) -> TimelineBuilder:
        from deepview.reporting.timeline import TimelineBuilder, TimelineEntry

        builder = TimelineBuilder()
        for f in findings:
            if f.timestamp is None:
                continue
            builder.add_entry(
                TimelineEntry(
                    timestamp=f.timestamp,
                    event_type=f.category,
                    description=f.title or f.name,
                    source=f.source or "finding",
                    severity=f.severity.value,
                    pid=f.pid,
                )
            )
        return builder

    def _build_process_tree(self):
        from deepview.analysis.process_tree import ProcessTree

        tree = ProcessTree()
        for items in self._context.artifacts.all_artifacts().values():
            for item in items:
                if not isinstance(item, dict):
                    continue
                pid = int(item.get("pid", 0) or 0)
                if pid <= 0:
                    continue
                ppid = int(item.get("ppid", 0) or 0)
                comm = str(item.get("comm") or item.get("process_name") or "")
                sev: EventSeverity = coerce_severity(item.get("severity", "info"))
                tree.add(pid, ppid, comm, severity=sev, count=1)
        return tree
