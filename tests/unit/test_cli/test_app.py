"""Tests for the Deep View CLI application (Click commands)."""
from __future__ import annotations

from click.testing import CliRunner

from deepview.cli.app import main
from deepview.core.logging import setup_logging


def _reconfigure_logging():
    """Re-configure structlog after CliRunner closes its captured stderr."""
    setup_logging("warning")


class TestMainGroup:
    """Tests for the root CLI group and its top-level commands."""

    def teardown_method(self):
        _reconfigure_logging()

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Deep View" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0

    def test_doctor_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
        assert result.exit_code == 0
        assert "Platform:" in result.output

    def test_plugins_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["plugins"])
        assert result.exit_code == 0

    def test_plugins_invalid_category(self):
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "--category", "nonexistent"])
        assert result.exit_code == 0
        assert "Unknown category" in result.output

    def test_invalid_log_level(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--log-level", "bogus", "doctor"])
        assert result.exit_code != 0
