"""Tests for the ``deepview sidechannel`` CLI group."""
from __future__ import annotations

import json

import click
from rich.console import Console
from click.testing import CliRunner

from deepview.cli.commands.sidechannel import sidechannel
from deepview.core.context import AnalysisContext


def _make_runner(context: AnalysisContext) -> tuple[CliRunner, click.Group]:
    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(sidechannel)
    return CliRunner(), _root


def test_probes_lists_builtins() -> None:
    runner, root = _make_runner(AnalysisContext.for_testing())
    result = runner.invoke(root, ["sidechannel", "probes"])
    assert result.exit_code == 0, result.output
    for name in ("simulated-squid", "dc-squid", "rf-squid"):
        assert name in result.output


def test_capture_requires_authorization() -> None:
    runner, root = _make_runner(AnalysisContext.for_testing())
    result = runner.invoke(root, ["sidechannel", "capture", "--subject", "dut"])
    assert result.exit_code != 0
    assert "authorization-statement is required" in result.output


def test_capture_dry_run_does_not_capture() -> None:
    ctx = AnalysisContext.for_testing()
    runner, root = _make_runner(ctx)
    result = runner.invoke(
        root,
        ["sidechannel", "capture", "--subject", "dut",
         "--authorization-statement", "ENG-2026-01"],
    )
    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "sidechannel_captures" not in ctx.artifacts.all_artifacts()


def test_capture_confirm_writes_and_records(tmp_path) -> None:
    ctx = AnalysisContext.for_testing()
    out = tmp_path / "cap.json"
    runner, root = _make_runner(ctx)
    result = runner.invoke(
        root,
        ["sidechannel", "capture", "--subject", "dut", "--device-class", "mcu",
         "--samples", "512", "--sample-rate", "500000",
         "--authorization-statement", "ENG-2026-01", "--confirm", "-o", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert "captured" in result.output
    payload = json.loads(out.read_text())
    assert payload["probe"] == "simulated-squid"
    assert len(payload["samples"]) == 512
    assert payload["authorization_statement"] == "ENG-2026-01"
    assert ctx.artifacts.all_artifacts()["sidechannel_captures"]


def test_capture_hardware_probe_unavailable_aborts() -> None:
    ctx = AnalysisContext.for_testing()
    runner, root = _make_runner(ctx)
    result = runner.invoke(
        root,
        ["sidechannel", "capture", "--probe", "dc-squid", "--subject", "dut",
         "--authorization-statement", "ENG-2026-01", "--confirm"],
    )
    assert result.exit_code != 0
    assert "not available" in result.output


def test_analyze_reports_dominant_frequency(tmp_path) -> None:
    import pytest

    pytest.importorskip("numpy")
    pytest.importorskip("scipy")
    ctx = AnalysisContext.for_testing()
    out = tmp_path / "cap.json"
    runner, root = _make_runner(ctx)
    runner.invoke(
        root,
        ["sidechannel", "capture", "--subject", "dut", "--samples", "8192",
         "--sample-rate", "1000000", "--signal-hz", "40000",
         "--authorization-statement", "ENG-2026-01", "--confirm", "-o", str(out)],
    )
    result = runner.invoke(
        root, ["sidechannel", "analyze", "--capture", str(out), "--nperseg", "2048"]
    )
    assert result.exit_code == 0, result.output
    assert "dominant_frequency_hz" in result.output
