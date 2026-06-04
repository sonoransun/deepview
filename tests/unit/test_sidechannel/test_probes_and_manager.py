"""Side-channel probe + manager tests (no hardware required)."""
from __future__ import annotations

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    SideChannelCaptureCompletedEvent,
    SideChannelCaptureStartedEvent,
)
from deepview.core.types import PrivilegeLevel
from deepview.interfaces.sidechannel import ProbeCapture, SubjectUnderTest, serialize_samples
from deepview.sidechannel import (
    DCSquidProbe,
    RFSquidProbe,
    SideChannelManager,
    SimulatedSquidProbe,
)
from deepview.utils.hashing import hash_bytes


def _sut() -> SubjectUnderTest:
    return SubjectUnderTest(label="dut-1", device_class="mcu")


def test_manager_registers_builtin_probes() -> None:
    mgr = SideChannelManager.from_context(AnalysisContext.for_testing())
    assert mgr.probe_names() == ["dc-squid", "rf-squid", "simulated-squid"]


def test_simulated_capture_is_deterministic_and_hashed() -> None:
    probe = SimulatedSquidProbe(seed=42)
    a = probe.capture(_sut(), samples=2048, sample_rate_hz=1_000_000)
    b = SimulatedSquidProbe(seed=42).capture(_sut(), samples=2048, sample_rate_hz=1_000_000)
    assert isinstance(a, ProbeCapture)
    assert a.sample_count == 2048
    assert a.duration_s == pytest.approx(2048 / 1_000_000)
    # Deterministic across instances with the same seed.
    assert a.samples == b.samples
    assert a.hash_sha256 == b.hash_sha256
    # Hash matches the canonical serialization.
    assert a.hash_sha256 == hash_bytes(serialize_samples(a.samples))


def test_different_seed_changes_capture() -> None:
    a = SimulatedSquidProbe(seed=1).capture(_sut(), samples=512, sample_rate_hz=500_000)
    b = SimulatedSquidProbe(seed=2).capture(_sut(), samples=512, sample_rate_hz=500_000)
    assert a.hash_sha256 != b.hash_sha256


def test_capture_rejects_bad_args() -> None:
    probe = SimulatedSquidProbe()
    with pytest.raises(ValueError):
        probe.capture(_sut(), samples=0)
    with pytest.raises(ValueError):
        probe.capture(_sut(), samples=16, sample_rate_hz=0)


def test_rf_mode_differs_from_dc() -> None:
    dc = SimulatedSquidProbe(mode="dc", seed=5).capture(_sut(), samples=1024, sample_rate_hz=1_000_000)
    rf = SimulatedSquidProbe(mode="rf", seed=5).capture(_sut(), samples=1024, sample_rate_hz=1_000_000)
    assert dc.hash_sha256 != rf.hash_sha256


def test_manager_capture_publishes_events_and_records_artifact() -> None:
    ctx = AnalysisContext.for_testing()
    started: list[SideChannelCaptureStartedEvent] = []
    completed: list[SideChannelCaptureCompletedEvent] = []
    ctx.events.subscribe(SideChannelCaptureStartedEvent, started.append)
    ctx.events.subscribe(SideChannelCaptureCompletedEvent, completed.append)

    mgr = SideChannelManager.from_context(ctx)
    result = mgr.capture(SimulatedSquidProbe(seed=3), _sut(), samples=256, sample_rate_hz=250_000)

    assert len(started) == 1 and started[0].probe == "simulated-squid"
    assert len(completed) == 1
    assert completed[0].sha256 == result.hash_sha256
    artifacts = ctx.artifacts.all_artifacts()["sidechannel_captures"]
    assert artifacts[0]["sha256"] == result.hash_sha256
    assert artifacts[0]["subject"] == "dut-1"


def test_hardware_probes_unavailable_without_driver() -> None:
    # No `squidpy` driver installed → both report unavailable and refuse capture.
    dc = DCSquidProbe(driver="deepview_no_such_squid_driver")
    rf = RFSquidProbe(driver="deepview_no_such_squid_driver")
    assert dc.is_available() is False
    assert rf.is_available() is False
    assert dc.requires_privileges() is PrivilegeLevel.ROOT
    with pytest.raises(RuntimeError, match="unavailable"):
        dc.capture(_sut(), samples=16)
    with pytest.raises(RuntimeError, match="unavailable"):
        rf.capture(_sut(), samples=16)
