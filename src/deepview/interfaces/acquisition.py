from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from deepview.core.types import (
    AcquisitionResult,
    AcquisitionTarget,
    DumpFormat,
    Platform,
    PrivilegeLevel,
)


class MemoryAcquisitionProvider(ABC):
    """Abstract provider for acquiring memory dumps from live systems."""

    @abstractmethod
    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        """Capture memory from *target* and write the dump to *output*."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` when this provider can operate on the current host."""

    @abstractmethod
    def supported_platforms(self) -> list[Platform]:
        """Platforms on which this provider can acquire memory."""

    @abstractmethod
    def requires_privileges(self) -> PrivilegeLevel:
        """Minimum privilege level needed to perform an acquisition."""

    @classmethod
    @abstractmethod
    def provider_name(cls) -> str:
        """Human-readable name for this acquisition provider."""
