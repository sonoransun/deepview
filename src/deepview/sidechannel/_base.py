"""Shared template for SQUID magnetometer probes.

Subclasses supply :meth:`_read_samples`; :meth:`capture` orchestrates the read
plus the SHA256 chain-of-custody so every concrete probe (simulated, DC-SQUID,
RF-SQUID) shares one acquisition path.
"""
from __future__ import annotations

from abc import abstractmethod

from deepview.core.types import Platform, PrivilegeLevel
from deepview.interfaces.sidechannel import (
    ProbeCapture,
    SideChannelProbe,
    SubjectUnderTest,
    serialize_samples,
)
from deepview.utils.hashing import hash_bytes


class MagnetometerProbe(SideChannelProbe):
    """Template probe for flux-magnetometry side channels."""

    channel = "magnetic"
    units = "phi0"
    default_sample_rate_hz = 1_000_000

    @abstractmethod
    def _read_samples(self, count: int, sample_rate_hz: int) -> list[float]:
        """Return ``count`` raw flux readings sampled at ``sample_rate_hz``."""

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.USER

    def capture(
        self,
        subject: SubjectUnderTest,
        *,
        samples: int = 4096,
        sample_rate_hz: int | None = None,
    ) -> ProbeCapture:
        if samples <= 0:
            raise ValueError("samples must be positive")
        # None → probe default; an explicit 0 (or negative) is an error, not a
        # silent fallback (`0 or default` would mask it).
        rate = self.default_sample_rate_hz if sample_rate_hz is None else int(sample_rate_hz)
        if rate <= 0:
            raise ValueError("sample_rate_hz must be positive")
        data = self._read_samples(samples, rate)
        digest = hash_bytes(serialize_samples(data))
        return ProbeCapture(
            probe_name=self.probe_name(),
            subject=subject,
            sample_rate_hz=rate,
            samples=tuple(data),
            channel=self.channel,
            units=self.units,
            hash_sha256=digest,
        )
