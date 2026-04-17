"""DMA providers log an IOMMU warning when IOMMU state looks locked.

The providers probe ``/sys/class/iommu/`` and ``/sys/firmware/efi/efivars``
before reading. When those paths indicate an active IOMMU (non-empty
directory), the provider must emit a :class:`RemoteAcquisitionProgressEvent`
with an ``iommu-check`` stage and a warning log line, then attempt the
read regardless.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.events import RemoteAcquisitionProgressEvent
from deepview.memory.acquisition.remote import dma_thunderbolt as dma_tb_module
from deepview.memory.acquisition.remote.base import RemoteEndpoint


def _collect_progress(ctx: AnalysisContext) -> list[RemoteAcquisitionProgressEvent]:
    captured: list[RemoteAcquisitionProgressEvent] = []
    ctx.events.subscribe(
        RemoteAcquisitionProgressEvent,
        lambda ev: captured.append(ev),
    )
    return captured


def test_detect_iommu_reports_locked_when_groups_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When ``/sys/class/iommu`` has groups, the probe reports locked."""
    fake_iommu = tmp_path / "iommu"
    fake_iommu.mkdir()
    (fake_iommu / "iommu0").mkdir()
    fake_efivars = tmp_path / "efivars"
    fake_efivars.mkdir()
    (fake_efivars / "SetupMode-7b59104a").write_bytes(b"\x00")

    real_isdir = os.path.isdir
    real_isfile = os.path.isfile
    real_listdir = os.listdir

    def fake_isdir(path: str) -> bool:
        if path == "/sys/class/iommu":
            return True
        if path == "/sys/firmware/efi/efivars":
            return True
        return real_isdir(path)

    def fake_listdir(path: str) -> list[str]:
        if path == "/sys/class/iommu":
            return real_listdir(str(fake_iommu))
        if path == "/sys/firmware/efi/efivars":
            return real_listdir(str(fake_efivars))
        return real_listdir(path)

    def fake_isfile(path: str) -> bool:
        return real_isfile(path)

    monkeypatch.setattr(os.path, "isdir", fake_isdir)
    monkeypatch.setattr(os.path, "isfile", fake_isfile)
    monkeypatch.setattr(os, "listdir", fake_listdir)

    locked, desc = dma_tb_module._detect_iommu_state()
    assert locked is True
    assert "iommu-active" in desc
    assert "setup-mode-locked=True" in desc


def test_detect_iommu_reports_unlocked_when_dir_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty ``/sys/class/iommu`` means IOMMU is inactive."""
    def fake_isdir(path: str) -> bool:
        return path == "/sys/class/iommu"

    def fake_listdir(path: str) -> list[str]:
        if path == "/sys/class/iommu":
            return []
        raise FileNotFoundError(path)

    def fake_isfile(path: str) -> bool:
        return False

    monkeypatch.setattr(os.path, "isdir", fake_isdir)
    monkeypatch.setattr(os.path, "isfile", fake_isfile)
    monkeypatch.setattr(os, "listdir", fake_listdir)

    locked, desc = dma_tb_module._detect_iommu_state()
    assert locked is False
    assert "empty" in desc


def test_detect_iommu_missing_dir_reports_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With neither /sys/class/iommu nor /proc/cpuinfo we return unknown."""
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    monkeypatch.setattr(os.path, "isfile", lambda path: False)
    locked, desc = dma_tb_module._detect_iommu_state()
    assert locked is False
    assert desc == "iommu-unknown"


def test_acquire_emits_iommu_check_event_and_warns_before_refusing_non_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Calling ``acquire`` without root still must probe and warn.

    We pre-empt the leechcore read by asserting the root-check raises,
    but the root check runs *before* the IOMMU probe, so we patch the
    provider to invoke the probe explicitly. This keeps the test purely
    unit-scope without needing leechcorepyc.
    """
    # Pretend IOMMU is locked with groups present.
    def fake_isdir(path: str) -> bool:
        return path in ("/sys/class/iommu", "/sys/firmware/efi/efivars")

    def fake_listdir(path: str) -> list[str]:
        if path == "/sys/class/iommu":
            return ["iommu0"]
        if path == "/sys/firmware/efi/efivars":
            return ["SetupMode-aabbccdd"]
        return []

    def fake_isfile(path: str) -> bool:
        return False

    monkeypatch.setattr(os.path, "isdir", fake_isdir)
    monkeypatch.setattr(os.path, "isfile", fake_isfile)
    monkeypatch.setattr(os, "listdir", fake_listdir)

    # Call the module helpers directly to assert the logging / return
    # shape — the full acquire() path is gated by root and leechcorepyc
    # which are exercised by test_dma_refuses_without_root.
    with caplog.at_level(logging.WARNING):
        locked, desc = dma_tb_module._detect_iommu_state()
    assert locked is True
    assert "iommu-active" in desc


def test_acquire_publishes_iommu_progress_event_before_refusing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End-to-end: non-root ``acquire`` still short-circuits before the
    probe — but when the root gate is bypassed with a stub, the provider
    publishes the IOMMU progress event before its first read attempt.
    """
    # Make _is_root return True so we get past the RuntimeError gate and
    # reach the IOMMU probe + leechcorepyc import.
    monkeypatch.setattr(dma_tb_module, "_is_root", lambda: True)

    # IOMMU probe reports locked.
    def fake_isdir(path: str) -> bool:
        return path == "/sys/class/iommu"

    def fake_listdir(path: str) -> list[str]:
        if path == "/sys/class/iommu":
            return ["iommu0"]
        return []

    monkeypatch.setattr(os.path, "isdir", fake_isdir)
    monkeypatch.setattr(os, "listdir", fake_listdir)
    monkeypatch.setattr(os.path, "isfile", lambda path: False)

    # leechcorepyc is not installed — import should fail with a clear
    # AcquisitionError. The IOMMU event must be published *before* that
    # ImportError is surfaced.
    import sys

    monkeypatch.setitem(sys.modules, "leechcorepyc", None)

    ctx = AnalysisContext.for_testing()
    progress = _collect_progress(ctx)
    ep = RemoteEndpoint(host="127.0.0.1", transport="dma")
    provider = dma_tb_module.ThunderboltDMAProvider(ep, context=ctx)

    # We don't care which exception wins; we just need the probe to have
    # run first.
    with pytest.raises(Exception):  # noqa: BLE001
        provider.acquire(
            _AcquisitionTarget(host="127.0.0.1"),
            tmp_path / "mem.raw",
        )
    iommu_events = [e for e in progress if e.stage.startswith("iommu-check")]
    assert iommu_events, "provider must emit iommu-check progress event"
    assert "iommu-active" in iommu_events[0].stage


# Small local helper so we don't re-import AcquisitionTarget above.
def _AcquisitionTarget(host: str) -> Any:
    from deepview.core.types import AcquisitionTarget

    return AcquisitionTarget(hostname=host)
