"""Tests for subprocess management utilities."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.exceptions import ToolNotFoundError
from deepview.utils.process import CommandResult, find_tool, run_command, run_command_async


class TestCommandResult:
    """Tests for the CommandResult dataclass."""

    def test_command_result_success(self):
        result = CommandResult(returncode=0, stdout="", stderr="")
        assert result.success is True

    def test_command_result_failure(self):
        result = CommandResult(returncode=1, stdout="", stderr="")
        assert result.success is False


class TestFindTool:
    """Tests for find_tool()."""

    def test_find_tool_exists(self):
        path = find_tool("python3")
        assert isinstance(path, Path)

    def test_find_tool_missing_raises(self):
        with pytest.raises(ToolNotFoundError):
            find_tool("nonexistent_tool_xyz")


class TestRunCommand:
    """Tests for run_command()."""

    def test_run_command_echo(self):
        result = run_command(["echo", "hello"])
        assert result.success
        assert "hello" in result.stdout

    def test_run_command_failure(self):
        result = run_command(["false"])
        assert not result.success


class TestRunCommandAsync:
    """Tests for run_command_async()."""

    @pytest.mark.asyncio
    async def test_run_command_async(self):
        result = await run_command_async(["echo", "async_test"])
        assert result.success
        assert "async_test" in result.stdout
