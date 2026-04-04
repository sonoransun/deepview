"""Tests for deepview.reporting.engine module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.reporting.engine import ReportEngine


@pytest.fixture
def context() -> AnalysisContext:
    return AnalysisContext.for_testing()


@pytest.fixture
def engine(context: AnalysisContext) -> ReportEngine:
    return ReportEngine(context)


class TestGenerateJSON:
    """Tests for ReportEngine.generate_json."""

    def test_generate_json_structure(self, engine: ReportEngine):
        """Verify all required keys present in JSON report."""
        report = engine.generate_json()

        assert "report_type" in report
        assert "version" in report
        assert "generated_at" in report
        assert "session_id" in report
        assert "platform" in report
        assert "artifacts" in report
        assert "layers" in report
        assert report["report_type"] == "deep_view_forensic_report"

    def test_generate_json_to_file(self, engine: ReportEngine, tmp_path: Path):
        """Verify JSON report is written to file."""
        output = tmp_path / "report.json"
        report = engine.generate_json(output=output)

        assert output.exists()
        loaded = json.loads(output.read_text())
        assert loaded["report_type"] == "deep_view_forensic_report"
        assert loaded["session_id"] == report["session_id"]

    def test_generate_json_has_session_id(
        self, context: AnalysisContext, engine: ReportEngine
    ):
        """Verify session_id matches context."""
        report = engine.generate_json()
        assert report["session_id"] == context.session_id


class TestGenerateMarkdown:
    """Tests for ReportEngine.generate_markdown."""

    def test_generate_markdown_contains_headers(self, engine: ReportEngine):
        """Verify markdown contains the main report header."""
        md = engine.generate_markdown()
        assert "# Deep View Forensic Report" in md

    def test_generate_markdown_to_file(self, engine: ReportEngine, tmp_path: Path):
        """Verify markdown report is written to file."""
        output = tmp_path / "report.md"
        md = engine.generate_markdown(output=output)

        assert output.exists()
        content = output.read_text()
        assert "# Deep View Forensic Report" in content


class TestGenerateHTML:
    """Tests for ReportEngine.generate_html."""

    def test_generate_html_contains_doctype(self, engine: ReportEngine):
        """Verify HTML starts with DOCTYPE declaration."""
        html = engine.generate_html()
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_generate_html_to_file(self, engine: ReportEngine, tmp_path: Path):
        """Verify HTML report is written to file."""
        output = tmp_path / "report.html"
        html = engine.generate_html(output=output)

        assert output.exists()
        content = output.read_text()
        assert content.strip().startswith("<!DOCTYPE html>")

    def test_generate_html_escapes_xss(self, context: AnalysisContext):
        """Verify HTML output escapes XSS payloads in artifact data."""
        context.artifacts.add(
            "test_cat<script>", {"key": "<img onerror=alert(1)>"}
        )
        engine = ReportEngine(context)
        html = engine.generate_html()

        # The category name is .title()'d then escaped, so <Script> becomes &lt;Script&gt;
        assert "&lt;Script&gt;" in html
        # Ensure no raw <script> tags appear in the body (outside the <style> block)
        body_html = html.split("</style>")[-1]
        assert "<script>" not in body_html.lower()

        # The artifact value should be escaped
        assert "&lt;img onerror=alert(1)&gt;" in html
        assert "<img onerror=alert(1)>" not in html
