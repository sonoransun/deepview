"""Side-channel analysis tests (numpy/scipy — skip-gated)."""
from __future__ import annotations

import pytest

from deepview.interfaces.sidechannel import SubjectUnderTest
from deepview.sidechannel import SimulatedSquidProbe

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")

from deepview.sidechannel import analysis  # noqa: E402


def _capture(signal_hz: float, seed: int = 1):
    probe = SimulatedSquidProbe(mode="dc", signal_hz=signal_hz, noise=0.01, seed=seed)
    return probe.capture(
        SubjectUnderTest(label="dut"), samples=8192, sample_rate_hz=1_000_000
    )


def test_dominant_frequency_recovers_signal() -> None:
    cap = _capture(40_000.0)
    dominant = analysis.dominant_frequency(cap, nperseg=2048)
    # Within one Welch bin of the injected 40 kHz tone.
    bin_width = cap.sample_rate_hz / 2048
    assert abs(dominant - 40_000.0) <= bin_width


def test_psd_shapes() -> None:
    cap = _capture(12_500.0)
    freqs, psd = analysis.power_spectral_density(cap, nperseg=1024)
    assert freqs.shape == psd.shape
    assert freqs[0] == 0.0
    assert psd.max() > 0.0


def test_correlation_identity_and_mismatch() -> None:
    cap = _capture(20_000.0)
    same = analysis.correlation(cap.samples, cap.samples)
    assert same == pytest.approx(1.0, abs=1e-9)
    with pytest.raises(ValueError):
        analysis.correlation(cap.samples, cap.samples[:10])


def test_leakage_snr_detects_class_dependence() -> None:
    # Two classes whose mean traces differ → high SNR.
    class_a = [_capture(10_000.0, seed=s) for s in range(4)]
    class_b = [_capture(80_000.0, seed=s) for s in range(4)]
    snr = analysis.leakage_snr({"a": class_a, "b": class_b})
    assert snr > 1.0

    # A single class cannot yield an SNR.
    with pytest.raises(ValueError):
        analysis.leakage_snr({"only": class_a})
