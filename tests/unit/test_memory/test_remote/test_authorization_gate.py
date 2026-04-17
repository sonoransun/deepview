"""Authorization-gate tests for ``deepview remote-image ssh``."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from deepview.cli.app import main


def test_ssh_without_confirm_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "remote-image", "ssh",
            "--host", "127.0.0.1",
            "--output", "/tmp/_dv_should_never_exist",
            "--dry-run",
        ],
    )
    # --confirm missing => click.UsageError (exit code 2).
    assert result.exit_code != 0
    assert "--confirm" in result.output or "confirm" in result.output.lower()


def test_ssh_without_authorization_statement_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "remote-image", "ssh",
            "--host", "127.0.0.1",
            "--confirm",
            "--output", str(tmp_path / "out.bin"),
            "--known-hosts", str(tmp_path / "khosts"),
            "--dry-run",
        ],
    )
    assert result.exit_code != 0
    assert "authorization" in result.output.lower()


def test_ssh_with_confirm_and_statement_proceeds_in_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    stmt = tmp_path / "auth.txt"
    stmt.write_text("I attest authorization for host 127.0.0.1 on 2026-04-14")
    khosts = tmp_path / "khosts"
    khosts.write_text("")  # non-empty-path check only at provider layer
    result = runner.invoke(
        main,
        [
            "remote-image", "ssh",
            "--host", "127.0.0.1",
            "--confirm",
            "--authorization-statement", f"file:{stmt}",
            "--known-hosts", str(khosts),
            "--output", str(tmp_path / "mem.raw"),
            "--dry-run",
        ],
    )
    # Dry-run path should not touch the network and should exit cleanly.
    assert result.exit_code == 0, result.output
    assert "plan:" in result.output
    assert "127.0.0.1" in result.output


def test_ssh_without_known_hosts_aborts_even_with_confirm(tmp_path: Path) -> None:
    """require_tls=True default + missing known_hosts => refuse."""
    runner = CliRunner()
    stmt = tmp_path / "auth.txt"
    stmt.write_text("authorized")
    result = runner.invoke(
        main,
        [
            "remote-image", "ssh",
            "--host", "127.0.0.1",
            "--confirm",
            "--authorization-statement", f"file:{stmt}",
            "--output", str(tmp_path / "mem.raw"),
            "--dry-run",
        ],
    )
    assert result.exit_code != 0
    assert "known-hosts" in result.output.lower() or "known_hosts" in result.output.lower()
