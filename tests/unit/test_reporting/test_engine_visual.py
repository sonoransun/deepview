"""Tests for the visual ReportEngine (findings rollup + HTML render)."""
from __future__ import annotations

from datetime import datetime, timezone

from deepview.core.context import AnalysisContext
from deepview.core.findings import Finding
from deepview.core.types import EventSeverity
from deepview.reporting.engine import ReportEngine, summarize_findings


def _ctx_with_findings() -> AnalysisContext:
    ctx = AnalysisContext.for_testing()
    ctx.add_finding(
        Finding(
            name="injected_code",
            title="Injected code",
            severity=EventSeverity.CRITICAL,
            category="injection",
            description="anon RWX",
            attack_ids=["T1055"],
            timestamp=datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc),
            pid=1234,
            process_name="evil",
        )
    )
    ctx.add_finding(
        Finding(
            name="suspicious_thread",
            title="Suspicious thread",
            severity=EventSeverity.WARNING,
            attack_ids=["T1055.003"],
            timestamp=datetime(2026, 6, 9, 12, 0, 5, tzinfo=timezone.utc),
            pid=1234,
            process_name="evil",
        )
    )
    return ctx


class TestSummary:
    def test_rolls_up_severity_and_processes(self):
        ctx = _ctx_with_findings()
        from deepview.reporting.engine import iter_findings

        summary = summarize_findings(iter_findings(ctx))
        assert summary["total"] == 2
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["warning"] == 1
        # pid 1234 affected, worst severity critical, 2 findings.
        proc = summary["affected_processes"][0]
        assert proc["pid"] == 1234
        assert proc["severity"] == "critical"
        assert proc["count"] == 2
        assert ("T1055", 1) in summary["top_techniques"]


class TestHtml:
    def test_html_contains_all_visual_sections(self):
        html = ReportEngine(_ctx_with_findings()).generate_html()
        assert "<!DOCTYPE html>" in html
        assert "Event Timeline" in html
        assert "MITRE ATT&amp;CK Coverage" in html
        assert "Process Tree" in html
        # SVG visuals embedded inline.
        assert html.count("<svg") >= 3
        # finding rows rendered.
        assert "Injected code" in html
        assert "T1055" in html

    def test_html_writes_self_contained_file(self, tmp_path):
        out = tmp_path / "report.html"
        ReportEngine(_ctx_with_findings()).generate_html(output=out)
        text = out.read_text()
        assert text.startswith("<!DOCTYPE html>")
        # no external asset references.
        assert "src=" not in text
        assert "<link" not in text


class TestMarkdownJson:
    def test_markdown_has_summary(self):
        md = ReportEngine(_ctx_with_findings()).generate_markdown()
        assert "## Summary" in md
        assert "Total findings:** 2" in md

    def test_json_has_summary_and_findings(self):
        report = ReportEngine(_ctx_with_findings()).generate_json()
        assert report["summary"]["total"] == 2
        assert len(report["findings"]) == 2
