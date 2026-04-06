"""Tests for disassemble CLI commands."""
from __future__ import annotations

from click.testing import CliRunner

from deepview.cli.app import main
from deepview.core.logging import setup_logging


class TestDisassembleGroup:
    def teardown_method(self):
        setup_logging("warning")

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "--help"])
        assert result.exit_code == 0
        assert "Disassembly" in result.output

    def test_disasm_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "disasm", "--help"])
        assert result.exit_code == 0
        assert "--binary" in result.output
        assert "--engine" in result.output

    def test_decompile_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "decompile", "--help"])
        assert result.exit_code == 0
        assert "--function" in result.output

    def test_functions_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "functions", "--help"])
        assert result.exit_code == 0
        assert "--binary" in result.output

    def test_xrefs_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "xrefs", "--help"])
        assert result.exit_code == 0
        assert "--direction" in result.output

    def test_cfg_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "cfg", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_strings_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "strings", "--help"])
        assert result.exit_code == 0
        assert "--min-length" in result.output

    def test_disasm_requires_binary(self):
        runner = CliRunner()
        result = runner.invoke(main, ["disassemble", "disasm"])
        assert result.exit_code != 0
