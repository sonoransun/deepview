"""Tests for ``deepview report timeline`` and ``deepview report export``.

Both now read from the context artifact store: ``export`` reconstructs
``Detection`` objects for STIX/ATT&CK, ``timeline`` builds from timestamped
artifacts.
"""
from __future__ import annotations

import json

import click
from rich.console import Console
from click.testing import CliRunner

from deepview.cli.commands.report import report
from deepview.core.context import AnalysisContext


def _make_runner(context: AnalysisContext) -> tuple[CliRunner, click.Group]:
    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(report)
    return CliRunner(), _root


def _ctx_with_detection() -> AnalysisContext:
    ctx = AnalysisContext.for_testing()
    ctx.artifacts.add(
        "detections",
        {
            "name": "DKOM_HIDDEN_PROCESS",
            "severity": "critical",
            "description": "pid 1337 hidden from pslist",
            "pid": 1337,
            "technique": "T1014",
            "timestamp": "2026-06-03T12:00:00",
        },
    )
    return ctx


def test_export_stix_bundle() -> None:
    runner, root = _make_runner(_ctx_with_detection())
    result = runner.invoke(root, ["report", "export", "--format", "stix"])
    assert result.exit_code == 0, result.output
    # The printed bundle should be valid JSON with one indicator object.
    start = result.output.index("{")
    bundle = json.loads(result.output[start:])
    assert bundle["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in bundle["objects"])
    assert any("T1014" in json.dumps(o) for o in bundle["objects"])


def test_export_attck_layer_to_file(tmp_path) -> None:
    out = tmp_path / "layer.json"
    runner, root = _make_runner(_ctx_with_detection())
    result = runner.invoke(
        root, ["report", "export", "--format", "attck", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    layer = json.loads(out.read_text())
    assert layer["domain"] == "enterprise-attack"
    assert any(t["techniqueID"] == "T1014" for t in layer["techniques"])


def test_export_json_is_full_report() -> None:
    runner, root = _make_runner(_ctx_with_detection())
    result = runner.invoke(root, ["report", "export", "--format", "json"])
    assert result.exit_code == 0, result.output
    start = result.output.index("{")
    payload = json.loads(result.output[start:])
    assert payload["report_type"] == "deep_view_forensic_report"
    assert "detections" in payload["artifacts"]


def test_timeline_builds_from_timestamped_artifacts() -> None:
    runner, root = _make_runner(_ctx_with_detection())
    result = runner.invoke(root, ["report", "timeline"])
    assert result.exit_code == 0, result.output
    assert "1 timeline entr" in result.output
    assert "DKOM_HIDDEN_PROCESS" in result.output or "hidden from pslist" in result.output


def test_timeline_empty_when_no_timestamps() -> None:
    ctx = AnalysisContext.for_testing()
    ctx.artifacts.add("notes", {"name": "no-timestamp"})
    runner, root = _make_runner(ctx)
    result = runner.invoke(root, ["report", "timeline"])
    assert result.exit_code == 0, result.output
    assert "0 timeline entr" in result.output
