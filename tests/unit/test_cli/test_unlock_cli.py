"""Help-text tests for the ``deepview unlock`` command group.

The unlock group isn't registered in ``cli/app.py`` yet — the plan's
orchestration owner wires that up after reviewing dual-use framing — so
these tests invoke the group object directly. Actual unlock runs
depend on the offload + orchestrator slices and are covered by
``test_luks_unlock.py``.
"""
from __future__ import annotations

from click.testing import CliRunner

from deepview.cli.commands.unlock import unlock


def test_unlock_group_help() -> None:
    runner = CliRunner()
    result = runner.invoke(unlock, ["--help"])
    assert result.exit_code == 0
    assert "luks" in result.output
    assert "auto" in result.output


def test_unlock_luks_help_lists_all_options() -> None:
    runner = CliRunner()
    result = runner.invoke(unlock, ["luks", "--help"])
    assert result.exit_code == 0
    out = result.output
    for flag in (
        "--passphrase-env",
        "--keyfile",
        "--master-key-hex",
        "--mount",
        "--confirm",
        "--enable-write",
        "--offset",
        "--register-as",
    ):
        assert flag in out, f"expected {flag} in help output:\n{out}"


def test_unlock_auto_help_lists_all_options() -> None:
    runner = CliRunner()
    result = runner.invoke(unlock, ["auto", "--help"])
    assert result.exit_code == 0
    out = result.output
    for flag in (
        "--memory-dump",
        "--passphrase-list",
        "--keyfile",
        "--try-hidden",
        "--register-as-prefix",
    ):
        assert flag in out, f"expected {flag} in help output:\n{out}"


def test_unlock_luks_missing_image_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(unlock, ["luks", "/nonexistent/path.img"])
    # Click's built-in exists check fails with exit code 2.
    assert result.exit_code != 0
