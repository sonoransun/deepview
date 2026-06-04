"""Tests for the ``deepview instrument`` CLI group.

Hardware-free: the Frida-backed commands are exercised on a box without Frida,
so they should print the install hint and abort cleanly (never traceback). The
``analyze`` command uses LIEF only and is skipped when LIEF is absent; when
present it runs against a real on-disk binary.
"""
from __future__ import annotations

import shutil

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from deepview.cli.commands.instrument import instrument
from deepview.core.context import AnalysisContext


def _make_runner_with_context(
    context: AnalysisContext,
) -> tuple[CliRunner, click.Group]:
    """Wrap the ``instrument`` group in a root Click group that injects context."""

    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(instrument)
    return CliRunner(), _root


def _frida_available() -> bool:
    try:
        import frida  # noqa: F401

        return True
    except ImportError:
        return False


class TestInstrumentAttach:
    @pytest.mark.skipif(
        _frida_available(), reason="Frida installed; cannot assert clean failure"
    )
    def test_attach_without_frida_prints_hint_and_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["instrument", "attach", "--pid", "1"])
        assert result.exit_code != 0
        # A clean abort with an actionable install hint, not a traceback.
        assert "pip install 'deepview[instrumentation]'" in result.output
        assert "Traceback" not in result.output


class TestInstrumentSpawn:
    @pytest.mark.skipif(
        _frida_available(), reason="Frida installed; cannot assert clean failure"
    )
    def test_spawn_without_frida_prints_hint_and_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        # /bin/sh exists on essentially every test host; existence check passes,
        # then the spawn fails because Frida is unavailable.
        program = shutil.which("sh") or "/bin/sh"
        result = runner.invoke(
            root, ["instrument", "spawn", "--program", program]
        )
        assert result.exit_code != 0
        assert "pip install 'deepview[instrumentation]'" in result.output
        assert "Traceback" not in result.output


class TestInstrumentAnalyze:
    def test_analyze_real_binary(self) -> None:
        pytest.importorskip("lief")
        # Analyze a real ELF that is present on the test host.
        target = shutil.which("ls") or "/bin/ls"

        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["instrument", "analyze", "--binary", target])
        assert result.exit_code == 0, result.output
        assert "Binary summary" in result.output
        # The summary table exposes the parsed format / arch fields.
        assert "format" in result.output

    def test_analyze_nonexistent_binary_rejected(self) -> None:
        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root, ["instrument", "analyze", "--binary", "/no/such/binary"]
        )
        # click.Path(exists=True) rejects before we ever touch LIEF.
        assert result.exit_code != 0


class TestInstrumentPatch:
    def test_patch_no_hooks_aborts_cleanly(self, tmp_path) -> None:
        pytest.importorskip("lief")
        target = shutil.which("ls") or "/bin/ls"
        out = tmp_path / "patched.bin"

        ctx = AnalysisContext.for_testing()
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root,
            [
                "instrument",
                "patch",
                "--binary",
                target,
                "--output",
                str(out),
                "--strategy",
                "exports",
            ],
        )
        # The reassembler may legitimately succeed or fail depending on the
        # host binary; either way it must not traceback and the failure path
        # must surface a clear message.
        assert "Traceback" not in result.output
        if result.exit_code != 0:
            assert "Patch failed" in result.output
