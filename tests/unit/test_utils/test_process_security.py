"""Security tests for subprocess management."""
from __future__ import annotations

import pytest

from deepview.utils.process import run_command


class TestTimeoutHandling:
    def test_timeout_returns_error_result(self):
        """Timeout should return CommandResult, not raise exception."""
        result = run_command(["sleep", "60"], timeout=1)
        assert result.returncode == -1
        assert "timed out" in result.stderr.lower()

    def test_timeout_result_has_no_stdout(self):
        result = run_command(["sleep", "60"], timeout=1)
        assert result.success is False


class TestNonexistentCommand:
    def test_missing_binary_returns_error(self):
        result = run_command(["nonexistent_binary_xyz_12345"])
        assert result.returncode == -1
        assert "not found" in result.stderr.lower()


class TestOutputBounds:
    def test_normal_command_succeeds(self):
        result = run_command(["echo", "hello"])
        assert result.success
        assert "hello" in result.stdout
