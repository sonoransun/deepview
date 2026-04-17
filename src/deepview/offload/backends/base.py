"""Abstract base class + stats dataclass for offload backends."""
from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import Future
from dataclasses import dataclass, field

from deepview.offload.jobs import OffloadJob, OffloadResult


@dataclass(frozen=True, slots=True)
class BackendStats:
    """Snapshot of a backend's runtime state reported by ``engine.status()``."""

    name: str
    available: bool
    capabilities: set[str] = field(default_factory=set)
    in_flight: int = 0


class OffloadBackend(ABC):
    """Abstract backend interface implemented by thread/process/GPU/remote pools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Registered backend name (e.g. ``"thread"``, ``"process"``, ``"gpu-opencl"``)."""

    @abstractmethod
    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        """Schedule *job* and return a stdlib future resolving to its :class:`OffloadResult`."""

    @abstractmethod
    def capabilities(self) -> set[str]:
        """Advertised capability tags (KDF kinds, ``"gpu"``, ``"io"``, ...)."""

    @abstractmethod
    def is_available(self) -> bool:
        """``True`` when the backend can accept jobs right now.

        For process/thread pools this is effectively always ``True``
        until :meth:`shutdown`; for GPU/remote pools this reports
        whether the optional dep imports + the device is reachable.
        """

    @abstractmethod
    def shutdown(self, wait: bool = True) -> None:
        """Stop accepting new jobs and release pool resources."""

    def in_flight(self) -> int:
        """Default 0; pool-backed backends override to report queued+running."""
        return 0

    def stats(self) -> BackendStats:
        return BackendStats(
            name=self.name,
            available=self.is_available(),
            capabilities=self.capabilities(),
            in_flight=self.in_flight(),
        )


__all__ = ["OffloadBackend", "BackendStats"]
