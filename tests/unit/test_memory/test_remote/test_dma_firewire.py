"""FireWire DMA provider: same root gate + optional-dep handling as PCIe."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.dma_firewire import FireWireDMAProvider


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def test_firewire_acquire_raises_runtime_error_without_root(tmp_path: Path) -> None:
    if _is_root():
        pytest.skip("running as root; cannot exercise the non-root gate")
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = FireWireDMAProvider(ep, context=AnalysisContext.for_testing())
    with pytest.raises(RuntimeError, match="root"):
        provider.acquire(
            AcquisitionTarget(hostname=ep.host),
            tmp_path / "mem.raw",
            DumpFormat.RAW,
        )


def test_firewire_is_available_false_without_forensic1394(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "forensic1394", None)
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = FireWireDMAProvider(ep, context=AnalysisContext.for_testing())
    assert provider.is_available() is False


def test_firewire_is_available_false_without_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with the library installed, non-root hosts are unavailable."""
    if _is_root():
        pytest.skip("running as root; cannot exercise the non-root gate")
    # Simulate forensic1394 being importable by injecting a stub.
    import types

    stub = types.SimpleNamespace(Bus=lambda: None)
    monkeypatch.setitem(sys.modules, "forensic1394", stub)
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = FireWireDMAProvider(ep, context=AnalysisContext.for_testing())
    assert provider.is_available() is False
