"""Deterministic simulated SQUID probe — no hardware, for tests and demos.

Synthesises a reproducible magnetic trace: a periodic, data-dependent emanation
(the kind a clocked crypto core radiates) plus deterministic pseudo-noise from a
seeded LCG. Same parameters -> identical samples -> identical SHA256, so the
capture and analysis pipelines are fully testable offline.
"""
from __future__ import annotations

import math

from deepview.sidechannel._base import MagnetometerProbe


class SimulatedSquidProbe(MagnetometerProbe):
    """A hardware-free magnetometer that emits a reproducible synthetic trace."""

    def __init__(
        self,
        *,
        mode: str = "dc",
        signal_hz: float = 12_500.0,
        amplitude: float = 1.0,
        noise: float = 0.05,
        seed: int = 1,
    ) -> None:
        if mode not in ("dc", "rf"):
            raise ValueError("mode must be 'dc' or 'rf'")
        self.mode = mode
        self.signal_hz = signal_hz
        self.amplitude = amplitude
        self.noise = noise
        self.seed = seed

    @classmethod
    def probe_name(cls) -> str:
        return "simulated-squid"

    def is_available(self) -> bool:
        return True

    def _read_samples(self, count: int, sample_rate_hz: int) -> list[float]:
        # Seeded LCG → repeatable pseudo-noise (no shared RNG state).
        state = (self.seed * 2654435761) & 0x7FFFFFFF
        out: list[float] = []
        omega = 2.0 * math.pi * self.signal_hz
        for n in range(count):
            t = n / sample_rate_hz
            state = (1103515245 * state + 12345) & 0x7FFFFFFF
            jitter = (state / 0x7FFFFFFF) - 0.5
            sample = self.amplitude * math.sin(omega * t)
            if self.mode == "rf":
                # rf-SQUID tank-circuit response adds a 2nd-harmonic component.
                sample += 0.3 * self.amplitude * math.sin(2.0 * omega * t)
            sample += self.noise * jitter
            out.append(sample)
        return out
