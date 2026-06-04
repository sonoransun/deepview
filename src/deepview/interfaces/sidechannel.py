"""Side-channel probe interface — magnetic / EM / power capture from a SUT.

DEFENSIVE / AUTHORIZED-TESTING SCOPE: these probes acquire physical
side-channel traces from a *subject under test* (SUT) you own and are
authorized to analyse — chip/board characterisation, leakage assessment,
CTF challenges, and hardware-security research. They do not target or
exfiltrate from third-party hardware. The ``deepview sidechannel`` CLI gates
capture behind an ``--authorization-statement``, mirroring remote acquisition.

rf-SQUID and dc-SQUID magnetometers are the canonical probes: a dc-SQUID
reads sample flux directly via a flux-locked loop, while an rf-SQUID couples
the sample into an RF tank circuit and reads the modulated response. Both land
here as :class:`SideChannelProbe` implementations producing :class:`ProbeCapture`
traces that the analysis helpers and the existing scanning/reporting code can
consume.
"""
from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from deepview.core.types import Platform, PrivilegeLevel
from deepview.utils.hashing import hash_bytes


@dataclass(frozen=True)
class SubjectUnderTest:
    """Chain-of-custody metadata for the device being probed."""

    label: str
    device_class: str = ""  # "smartcard" | "mcu" | "fpga" | "sram" | ...
    description: str = ""
    notes: str = ""


def serialize_samples(samples: Sequence[float]) -> bytes:
    """Canonical little-endian float64 serialization (basis for the SHA256)."""
    return struct.pack(f"<{len(samples)}d", *samples)


@dataclass(frozen=True)
class ProbeCapture:
    """A single side-channel acquisition.

    ``hash_sha256`` is taken over :func:`serialize_samples` so every capture
    carries the same integrity invariant as a memory ``AcquisitionResult``.
    """

    probe_name: str
    subject: SubjectUnderTest
    sample_rate_hz: int
    samples: tuple[float, ...]
    channel: str = "magnetic"  # magnetic | em | power
    units: str = "phi0"  # flux quanta (SQUID); volts (EM/power); ...
    metadata: Mapping[str, str] = field(default_factory=dict)
    hash_sha256: str = ""

    @property
    def sample_count(self) -> int:
        return len(self.samples)

    @property
    def duration_s(self) -> float:
        return self.sample_count / self.sample_rate_hz if self.sample_rate_hz else 0.0

    def with_hash(self) -> ProbeCapture:
        """Return a copy with ``hash_sha256`` populated if it is not already."""
        if self.hash_sha256:
            return self
        return replace(self, hash_sha256=hash_bytes(serialize_samples(self.samples)))


class SideChannelProbe(ABC):
    """Abstract magnetic/EM/power side-channel probe over a subject under test."""

    @classmethod
    @abstractmethod
    def probe_name(cls) -> str:
        """Stable identifier, e.g. ``"dc-squid"``."""

    @abstractmethod
    def is_available(self) -> bool:
        """True when the probe can actually capture (hardware/driver present)."""

    @abstractmethod
    def supported_platforms(self) -> list[Platform]:
        ...

    @abstractmethod
    def requires_privileges(self) -> PrivilegeLevel:
        ...

    @abstractmethod
    def capture(
        self,
        subject: SubjectUnderTest,
        *,
        samples: int = 4096,
        sample_rate_hz: int | None = None,
    ) -> ProbeCapture:
        """Acquire ``samples`` readings and return a hashed :class:`ProbeCapture`."""

    def open(self) -> None:
        """Acquire hardware handles (no-op by default)."""

    def close(self) -> None:
        """Release hardware handles (no-op by default)."""

    def __enter__(self) -> SideChannelProbe:
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
