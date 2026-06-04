"""Tests for the ``deepview scan`` command group (yara / ioc / rules).

The group is wired to ``YaraScanner`` / ``IndicatorEngine`` / ``RuleManager``.
The YARA path is skip-gated on ``yara-python``; the IoC and rules paths run
everywhere (pure-Python backends).
"""
from __future__ import annotations

import json

import click
import pytest
from rich.console import Console
from click.testing import CliRunner

from deepview.cli.commands.scan import scan
from deepview.core.context import AnalysisContext


def _make_runner(context: AnalysisContext) -> tuple[CliRunner, click.Group]:
    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(scan)
    return CliRunner(), _root


def test_rules_list_reports_rule_files(tmp_path) -> None:
    ctx = AnalysisContext.for_testing()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "malware.yar").write_text("rule t { condition: true }")
    (rules_dir / "creds.yara").write_text("rule c { condition: true }")
    ctx.config.memory.yara_rules_dir = rules_dir

    runner, root = _make_runner(ctx)
    result = runner.invoke(root, ["scan", "rules", "--list"])
    assert result.exit_code == 0, result.output
    assert "malware" in result.output
    assert "creds" in result.output


def test_rules_list_empty_dir(tmp_path) -> None:
    ctx = AnalysisContext.for_testing()
    ctx.config.memory.yara_rules_dir = tmp_path / "missing"
    runner, root = _make_runner(ctx)
    result = runner.invoke(root, ["scan", "rules"])
    assert result.exit_code == 0, result.output
    assert "No rule files found" in result.output


def test_ioc_matches_indicator_in_file(tmp_path) -> None:
    ctx = AnalysisContext.for_testing()
    ioc_file = tmp_path / "iocs.json"
    ioc_file.write_text(
        json.dumps(
            {"indicators": [{"type": "string", "value": "EVILSTRING", "severity": "high"}]}
        )
    )
    target = tmp_path / "sample.bin"
    target.write_bytes(b"....EVILSTRING....")

    runner, root = _make_runner(ctx)
    result = runner.invoke(
        root, ["scan", "ioc", "-t", str(target), "--ioc-file", str(ioc_file)]
    )
    assert result.exit_code == 0, result.output
    assert "EVILSTRING" in result.output
    assert "1 indicator match" in result.output


def test_ioc_no_match(tmp_path) -> None:
    ctx = AnalysisContext.for_testing()
    ioc_file = tmp_path / "iocs.json"
    ioc_file.write_text(
        json.dumps({"indicators": [{"type": "string", "value": "NOPE", "severity": "low"}]})
    )
    target = tmp_path / "clean.bin"
    target.write_bytes(b"nothing to see here")

    runner, root = _make_runner(ctx)
    result = runner.invoke(
        root, ["scan", "ioc", "-t", str(target), "--ioc-file", str(ioc_file)]
    )
    assert result.exit_code == 0, result.output
    assert "0 indicator match" in result.output


def test_yara_scan_file() -> None:
    pytest.importorskip("yara")
    ctx = AnalysisContext.for_testing()
    runner, root = _make_runner(ctx)
    with runner.isolated_filesystem():
        from pathlib import Path

        Path("rule.yar").write_text(
            'rule found_marker { strings: $a = "MARKERXYZ" condition: $a }'
        )
        Path("target.bin").write_bytes(b"junk MARKERXYZ junk")
        result = runner.invoke(
            root, ["scan", "yara", "-t", "target.bin", "-r", "rule.yar"]
        )
    assert result.exit_code == 0, result.output
    assert "found_marker" in result.output
    assert "1 match" in result.output
