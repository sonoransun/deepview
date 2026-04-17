"""Tests for the ``deepview offload`` CLI group.

Covers the three subcommands actually exposed by
:mod:`deepview.cli.commands.offload` — ``status``, ``run`` and
``benchmark``. The group is wrapped in a small Click shim that injects
an ``AnalysisContext`` + ``Console`` into ``ctx.obj``, mirroring the
pattern used by the ``storage`` and ``filesystem`` CLI test modules.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from deepview.cli.commands.offload import offload
from deepview.core.context import AnalysisContext


def _make_runner_with_context(
    context: AnalysisContext,
) -> tuple[CliRunner, click.Group]:
    """Wrap the ``offload`` group in a root group that injects context."""

    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200, no_color=True)

    _root.add_command(offload)
    return CliRunner(), _root


class TestOffloadHelp:
    def test_group_help_lists_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(offload, ["--help"])
        assert result.exit_code == 0
        out = result.output
        # The group should advertise its three subcommands.
        assert "status" in out
        assert "run" in out
        assert "benchmark" in out


class TestOffloadStatus:
    def test_status_renders_table_with_builtin_backends(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["offload", "status"])
        assert result.exit_code == 0, result.output
        # "thread" and "process" are the always-available backends that
        # OffloadEngine auto-registers on __init__.
        assert "thread" in result.output
        assert "process" in result.output
        assert "Offload backends" in result.output

    def test_status_reports_capabilities_column(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["offload", "status"])
        assert result.exit_code == 0, result.output
        # Table should contain a Capabilities column header.
        assert "Capabilities" in result.output


class TestOffloadRun:
    def _write_pbkdf2_payload(self, tmp_path: Path, iterations: int = 1) -> Path:
        payload = {
            "password_hex": b"hunter2".hex(),
            "salt_hex": b"saltsalt".hex(),
            "iterations": iterations,
            "dklen": 32,
        }
        path = tmp_path / "payload.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_run_pbkdf2_small_iteration_succeeds(self, tmp_path: Path) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        payload_path = self._write_pbkdf2_payload(tmp_path, iterations=1)
        result = runner.invoke(
            root,
            [
                "offload",
                "run",
                "--kind",
                "pbkdf2_sha256",
                "--json-input",
                str(payload_path),
            ],
        )
        assert result.exit_code == 0, result.output
        # Result is printed as JSON; parse it and ensure an output exists.
        # Find the JSON blob — Rich's print_json should emit a top-level
        # object with the expected keys.
        assert '"job_id"' in result.output
        assert '"ok"' in result.output

    def test_run_rejects_invalid_json(self, tmp_path: Path) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        result = runner.invoke(
            root,
            [
                "offload",
                "run",
                "--kind",
                "pbkdf2_sha256",
                "--json-input",
                str(bad),
            ],
        )
        assert result.exit_code != 0
        assert "Invalid JSON payload" in result.output

    def test_run_unknown_backend_errors_cleanly(self, tmp_path: Path) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        payload_path = self._write_pbkdf2_payload(tmp_path, iterations=1)
        result = runner.invoke(
            root,
            [
                "offload",
                "run",
                "--kind",
                "pbkdf2_sha256",
                "--json-input",
                str(payload_path),
                "--backend",
                "nonexistent-backend",
            ],
        )
        # Either Click refuses the option, or OffloadEngine raises; in
        # either case there should not be an unhandled traceback token.
        assert result.exit_code != 0
        # Guard against exposing an uncaught traceback to the operator.
        assert "Traceback (most recent call last)" not in result.output

    def test_run_unknown_kind_errors(self, tmp_path: Path) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        payload_path = self._write_pbkdf2_payload(tmp_path, iterations=1)
        result = runner.invoke(
            root,
            [
                "offload",
                "run",
                "--kind",
                "bogus",
                "--json-input",
                str(payload_path),
            ],
        )
        # Click.Choice should reject the value with exit code 2.
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output


class TestOffloadBenchmarkHelp:
    def test_benchmark_help_lists_flags(self) -> None:
        runner = CliRunner()
        result = runner.invoke(offload, ["benchmark", "--help"])
        assert result.exit_code == 0
        for flag in ("--kind", "--iterations", "--backend"):
            assert flag in result.output


# Keep the file lean — heavyweight KDF benchmarking is exercised by the
# unit tests under ``tests/unit/test_offload/`` so we don't re-run it
# here via the CLI front door.
pytest_plugins: tuple[str, ...] = ()
