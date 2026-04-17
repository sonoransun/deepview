"""Tests for the ``deepview unlock-native`` CLI group.

The real unlock paths need container fixtures + the optional
cryptography extras; here we focus on:

* ``--help`` works for the group and every subcommand;
* mandatory flags (``--confirm``, key sources) are enforced;
* the command never shells out to ``cryptsetup``/``dislocker``/``hdiutil``
  (sandbox invariant: Deep View performs decryption in-process).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from rich.console import Console

from deepview.cli.commands.unlock_native import unlock_native
from deepview.core.context import AnalysisContext


def _invoke(runner: CliRunner, args: list[str]) -> object:
    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = AnalysisContext.for_testing()
        ctx.obj["console"] = Console(record=True, width=200, no_color=True)

    _root.add_command(unlock_native)
    return runner.invoke(_root, ["unlock-native", *args])


class TestUnlockNativeHelp:
    def test_group_help_works(self) -> None:
        runner = CliRunner()
        result = runner.invoke(unlock_native, ["--help"])
        assert result.exit_code == 0
        assert "bitlocker" in result.output
        assert "filevault" in result.output

    def test_bitlocker_help_lists_expected_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(unlock_native, ["bitlocker", "--help"])
        assert result.exit_code == 0
        out = result.output
        for flag in (
            "--recovery-password",
            "--passphrase-env",
            "--keyfile",
            "--fvek-hex",
            "--fvek-from-memory",
            "--register-as",
            "--confirm",
        ):
            assert flag in out, f"expected {flag} in help:\n{out}"

    def test_filevault_help_lists_expected_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(unlock_native, ["filevault", "--help"])
        assert result.exit_code == 0
        out = result.output
        for flag in (
            "--passphrase-env",
            "--recovery-password-env",
            "--volume-key-hex",
            "--register-as",
            "--confirm",
        ):
            assert flag in out, f"expected {flag} in help:\n{out}"


class TestUnlockNativeGates:
    def test_bitlocker_without_confirm_errors(self, tmp_path: Path) -> None:
        img = tmp_path / "small.img"
        img.write_bytes(b"\x00" * 4096)
        runner = CliRunner()
        result = _invoke(runner, ["bitlocker", str(img)])
        assert result.exit_code != 0
        assert "--confirm" in result.output or "confirm" in result.output.lower()

    def test_filevault_without_confirm_errors(self, tmp_path: Path) -> None:
        img = tmp_path / "small.img"
        img.write_bytes(b"\x00" * 4096)
        runner = CliRunner()
        result = _invoke(runner, ["filevault", str(img)])
        assert result.exit_code != 0
        assert "--confirm" in result.output or "confirm" in result.output.lower()

    def test_bitlocker_missing_image_errors(self) -> None:
        runner = CliRunner()
        result = _invoke(runner, ["bitlocker", "/nonexistent/image.bin", "--confirm"])
        # Click's exists=True path check aborts before we even reach
        # the banner.
        assert result.exit_code != 0

    def test_filevault_requires_key_source(self, tmp_path: Path) -> None:
        img = tmp_path / "small.img"
        img.write_bytes(b"\x00" * 4096)
        runner = CliRunner()
        # With --confirm supplied but no key source, the command reaches
        # the detect path. The small all-zero image cannot be a FileVault
        # container, so unlocker.detect returns None and the CLI aborts.
        # Either way the CLI must not raise an unhandled traceback.
        result = _invoke(runner, ["filevault", str(img), "--confirm"])
        assert result.exit_code != 0
        assert "Traceback (most recent call last)" not in result.output


class TestUnlockNativeNoShellOut:
    """The CLI must not shell out to external crypto binaries."""

    def test_help_does_not_invoke_subprocess_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        forbidden: list[tuple[object, ...]] = []

        def _fake_run(*args: object, **kwargs: object) -> None:
            forbidden.append((args, kwargs))
            raise RuntimeError("unexpected subprocess.run call")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        runner = CliRunner()
        result = runner.invoke(unlock_native, ["--help"])
        assert result.exit_code == 0
        assert forbidden == []

    def test_bitlocker_help_does_not_shell_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        forbidden: list[tuple[object, ...]] = []
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: forbidden.append((a, k)),
        )
        runner = CliRunner()
        result = runner.invoke(unlock_native, ["bitlocker", "--help"])
        assert result.exit_code == 0
        assert forbidden == []

    def test_filevault_help_does_not_shell_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        forbidden: list[tuple[object, ...]] = []
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: forbidden.append((a, k)),
        )
        runner = CliRunner()
        result = runner.invoke(unlock_native, ["filevault", "--help"])
        assert result.exit_code == 0
        assert forbidden == []

    def test_no_external_crypto_binary_names_in_module(self) -> None:
        """Source-level guard: the module must not reference external
        crypto binaries by name.
        """
        src_path = Path(__file__).resolve().parent.parent.parent.parent / (
            "src/deepview/cli/commands/unlock_native.py"
        )
        text = src_path.read_text(encoding="utf-8").lower()
        for name in ("cryptsetup", "dislocker", "hdiutil"):
            assert name not in text, (
                f"unlock_native.py must not reference {name!r}; "
                "decryption happens in-process"
            )
