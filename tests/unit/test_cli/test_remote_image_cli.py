"""Tests for the ``deepview remote-image`` CLI group.

Focus on the dual-use gates (``--confirm``, ``--authorization-statement``,
``--enable-dma``, root check) rather than the actual transport
behaviour — each provider has its own provider-level tests under
``tests/unit/test_memory/test_remote/``.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from deepview.cli.commands.remote_image import remote_image


def _invoke(
    runner: CliRunner,
    args: list[str],
) -> object:
    """Invoke through a shim root group that builds the expected ctx.obj."""
    import click
    from rich.console import Console

    from deepview.core.context import AnalysisContext

    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = AnalysisContext.for_testing()
        ctx.obj["console"] = Console(record=True, width=200, no_color=True)

    _root.add_command(remote_image)
    return runner.invoke(_root, ["remote-image", *args])


class TestRemoteImageHelp:
    def test_group_help_lists_transport_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(remote_image, ["--help"])
        assert result.exit_code == 0
        out = result.output
        # At least these transports must be reachable from the CLI.
        for sub in ("ssh", "tcp", "agent", "lime", "dma-tb", "dma-pcie",
                    "dma-fw", "ipmi", "amt"):
            assert sub in out, f"missing subcommand {sub!r} in help:\n{out}"


class TestSSHGate:
    def test_ssh_dry_run_requires_confirm(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = _invoke(
            runner,
            [
                "ssh",
                "--host", "127.0.0.1",
                "--username", "user",
                "--output", str(tmp_path / "mem.raw"),
                "--dry-run",
            ],
        )
        assert result.exit_code != 0
        assert "confirm" in result.output.lower()

    def test_ssh_without_auth_statement_errors(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = _invoke(
            runner,
            [
                "ssh",
                "--host", "10.0.0.5",
                "--username", "user",
                "--confirm",
                "--known-hosts", str(tmp_path / "known_hosts"),
                "--output", str(tmp_path / "mem.raw"),
                "--dry-run",
            ],
        )
        assert result.exit_code != 0
        assert "authorization" in result.output.lower()
        # No traceback surfaced to the operator.
        assert "Traceback (most recent call last)" not in result.output

    def test_ssh_dry_run_happy_path(self, tmp_path: Path) -> None:
        runner = CliRunner()
        stmt = tmp_path / "auth.txt"
        stmt.write_text("ops ticket 2026-04-16", encoding="utf-8")
        khosts = tmp_path / "known_hosts"
        khosts.write_text("", encoding="utf-8")
        result = _invoke(
            runner,
            [
                "ssh",
                "--host", "10.0.0.5",
                "--username", "user",
                "--confirm",
                "--authorization-statement", f"file:{stmt}",
                "--known-hosts", str(khosts),
                "--output", str(tmp_path / "mem.raw"),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        # The dry-run helper prints a "plan:" line mentioning the host.
        assert "plan:" in result.output
        assert "10.0.0.5" in result.output


class TestDMAGate:
    """The DMA subcommands must refuse to run without --enable-dma, AND
    (when --enable-dma is supplied) must refuse on non-root."""

    def test_dma_tb_without_enable_dma_refuses(
        self, tmp_path: Path,
    ) -> None:
        runner = CliRunner()
        stmt = tmp_path / "auth.txt"
        stmt.write_text("dma authorized", encoding="utf-8")
        result = _invoke(
            runner,
            [
                "dma-tb",
                "--host", "127.0.0.1",
                "--confirm",
                "--authorization-statement", f"file:{stmt}",
                "--output", str(tmp_path / "mem.raw"),
                "--dry-run",
            ],
        )
        assert result.exit_code != 0
        # The preflight uses the literal phrase "--enable-dma".
        assert "--enable-dma" in result.output or "enable-dma" in result.output

    def test_dma_tb_with_enable_dma_but_non_root_refuses(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Simulate non-root via monkeypatching ``os.geteuid``."""
        if not hasattr(os, "geteuid"):
            pytest.skip("os.geteuid not available on this platform")
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        runner = CliRunner()
        stmt = tmp_path / "auth.txt"
        stmt.write_text("dma authorized", encoding="utf-8")
        result = _invoke(
            runner,
            [
                "dma-tb",
                "--host", "127.0.0.1",
                "--confirm",
                "--authorization-statement", f"file:{stmt}",
                "--output", str(tmp_path / "mem.raw"),
                "--enable-dma",
                "--dry-run",
            ],
        )
        assert result.exit_code != 0
        # Root-refusal message uses "ROOT" per the module.
        assert "root" in result.output.lower()

    def test_dma_pcie_without_enable_dma_refuses(
        self, tmp_path: Path,
    ) -> None:
        runner = CliRunner()
        stmt = tmp_path / "auth.txt"
        stmt.write_text("dma authorized", encoding="utf-8")
        result = _invoke(
            runner,
            [
                "dma-pcie",
                "--host", "127.0.0.1",
                "--confirm",
                "--authorization-statement", f"file:{stmt}",
                "--output", str(tmp_path / "mem.raw"),
                "--dry-run",
            ],
        )
        assert result.exit_code != 0
        assert "enable-dma" in result.output

    def test_dma_fw_without_enable_dma_refuses(
        self, tmp_path: Path,
    ) -> None:
        runner = CliRunner()
        stmt = tmp_path / "auth.txt"
        stmt.write_text("dma authorized", encoding="utf-8")
        result = _invoke(
            runner,
            [
                "dma-fw",
                "--host", "127.0.0.1",
                "--confirm",
                "--authorization-statement", f"file:{stmt}",
                "--output", str(tmp_path / "mem.raw"),
                "--dry-run",
            ],
        )
        assert result.exit_code != 0
        assert "enable-dma" in result.output
