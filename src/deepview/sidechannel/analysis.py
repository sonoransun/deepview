"""Side-channel trace analysis: PSD, correlation, and leakage/SNR assessment.

numpy/scipy are imported lazily (the ``sidechannel`` extra); on a core install
the helpers raise a clear, actionable error. The load-bearing maths lives in
small pure functions so they can be unit-tested directly.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from deepview.interfaces.sidechannel import ProbeCapture

if TYPE_CHECKING:
    import numpy as _np


def _require_numpy() -> Any:
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        raise RuntimeError(
            "side-channel analysis requires numpy "
            "(pip install 'deepview[sidechannel]')"
        ) from exc
    return np


def _require_scipy_signal() -> Any:
    try:
        from scipy import signal  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        raise RuntimeError(
            "PSD analysis requires scipy (pip install 'deepview[sidechannel]')"
        ) from exc
    return signal


def power_spectral_density(
    capture: ProbeCapture, *, nperseg: int = 256
) -> tuple[_np.ndarray, _np.ndarray]:
    """Welch power spectral density. Returns ``(freqs_hz, psd)`` arrays."""
    np = _require_numpy()
    signal = _require_scipy_signal()
    data = np.asarray(capture.samples, dtype=np.float64)
    seg = min(nperseg, len(data)) or 1
    freqs, psd = signal.welch(data, fs=capture.sample_rate_hz, nperseg=seg)
    return freqs, psd


def dominant_frequency(capture: ProbeCapture, *, nperseg: int = 256) -> float:
    """Frequency (Hz) of the strongest spectral component in *capture*."""
    np = _require_numpy()
    freqs, psd = power_spectral_density(capture, nperseg=nperseg)
    return float(freqs[int(np.argmax(psd))])


def correlation(a: Sequence[float], b: Sequence[float]) -> float:
    """Pearson correlation between two equal-length traces (0.0 if degenerate)."""
    np = _require_numpy()
    av = np.asarray(a, dtype=np.float64)
    bv = np.asarray(b, dtype=np.float64)
    if av.shape != bv.shape or av.size == 0:
        raise ValueError("traces must be equal-length and non-empty")
    if float(av.std()) == 0.0 or float(bv.std()) == 0.0:
        return 0.0
    return float(np.corrcoef(av, bv)[0, 1])


def leakage_snr(captures_by_class: dict[str, list[ProbeCapture]]) -> float:
    """First-order leakage SNR across >=2 classes of equal-length captures.

    SNR = max_t( var_over_classes(mean_t) / mean_over_classes(var_t) ). A high
    value means the trace varies with the class label (i.e. it leaks).
    """
    np = _require_numpy()
    class_means: list[Any] = []
    class_vars: list[Any] = []
    length: int | None = None
    for caps in captures_by_class.values():
        if not caps:
            continue
        mat = np.array([list(c.samples) for c in caps], dtype=np.float64)
        if length is None:
            length = mat.shape[1]
        elif mat.shape[1] != length:
            raise ValueError("all captures must share the same sample count")
        class_means.append(mat.mean(axis=0))
        class_vars.append(mat.var(axis=0))
    if len(class_means) < 2:
        raise ValueError("need >= 2 non-empty classes for an SNR estimate")
    signal_var = np.var(np.array(class_means), axis=0)
    noise_var = np.mean(np.array(class_vars), axis=0)
    eps = np.finfo(np.float64).eps
    noise_var = np.where(noise_var == 0.0, eps, noise_var)
    return float(np.max(signal_var / noise_var))
