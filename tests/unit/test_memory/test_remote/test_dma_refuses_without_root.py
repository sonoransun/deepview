"""DMA providers refuse to operate without root and without leechcore."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from deepview.cli.app import main
from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.dma_pcie import PCIeDMAProvider
from deepview.memory.acquisition.remote.dma_thunderbolt import ThunderboltDMAProvider


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def test_dma_tb_acquire_raises_runtime_error_without_root(tmp_path: Path) -> None:
    """Without root, :meth:`acquire` raises a clear RuntimeError."""
    if _is_root():
        pytest.skip("running as root; cannot exercise the non-root gate")
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = ThunderboltDMAProvider(ep, context=AnalysisContext.for_testing())
    with pytest.raises(RuntimeError, match="root"):
        provider.acquire(
            AcquisitionTarget(hostname=ep.host),
            tmp_path / "mem.raw",
            DumpFormat.RAW,
        )


def test_dma_pcie_acquire_raises_runtime_error_without_root(tmp_path: Path) -> None:
    """PCIe DMA provider enforces the same gate."""
    if _is_root():
        pytest.skip("running as root; cannot exercise the non-root gate")
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = PCIeDMAProvider(ep, context=AnalysisContext.for_testing())
    with pytest.raises(RuntimeError, match="root"):
        provider.acquire(
            AcquisitionTarget(hostname=ep.host),
            tmp_path / "mem.raw",
            DumpFormat.RAW,
        )


def test_dma_tb_is_available_false_without_leechcore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the optional leechcorepyc dep, is_available() is False."""
    # Simulate leechcorepyc not being importable.
    monkeypatch.setitem(sys.modules, "leechcorepyc", None)
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = ThunderboltDMAProvider(ep, context=AnalysisContext.for_testing())
    assert provider.is_available() is False


def test_dma_pcie_is_available_false_without_leechcore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "leechcorepyc", None)
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = PCIeDMAProvider(ep, context=AnalysisContext.for_testing())
    assert provider.is_available() is False


def test_dma_cli_refuses_without_enable_dma(tmp_path: Path) -> None:
    """Even with --confirm + authorization, DMA subcommands need --enable-dma."""
    runner = CliRunner()
    stmt = tmp_path / "auth.txt"
    stmt.write_text("authorized")
    result = runner.invoke(
        main,
        [
            "remote-image", "dma-tb",
            "--host", "127.0.0.1",
            "--confirm",
            "--authorization-statement", f"file:{stmt}",
            "--output", str(tmp_path / "mem.raw"),
            "--no-require-tls",
            "--dry-run",
        ],
    )
    assert result.exit_code != 0
    assert "--enable-dma" in result.output


def test_dma_cli_refuses_non_root(tmp_path: Path) -> None:
    """Without root, DMA subcommands abort at the CLI gate even with --enable-dma."""
    if _is_root():
        pytest.skip("running as root; cannot exercise the non-root gate")
    runner = CliRunner()
    stmt = tmp_path / "auth.txt"
    stmt.write_text("authorized")
    result = runner.invoke(
        main,
        [
            "remote-image", "dma-tb",
            "--host", "127.0.0.1",
            "--confirm",
            "--authorization-statement", f"file:{stmt}",
            "--output", str(tmp_path / "mem.raw"),
            "--no-require-tls",
            "--enable-dma",
            "--dry-run",
        ],
    )
    assert result.exit_code != 0
    assert "root" in result.output.lower()
