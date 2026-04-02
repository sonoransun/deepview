from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.types import ScanResult

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer


class PatternScanner(ABC):
    """Abstract interface for byte-pattern / YARA-style scanning."""

    @abstractmethod
    def scan(self, data: bytes, offset: int = 0) -> Iterator[ScanResult]:
        """Scan an in-memory *data* buffer, reporting matches relative to
        *offset*."""

    @abstractmethod
    def scan_layer(
        self,
        layer: DataLayer,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        """Scan an entire :class:`DataLayer`, optionally reporting progress."""

    @abstractmethod
    def load_rules(self, path: Path) -> None:
        """Load pattern / YARA rules from *path*."""

    @property
    @abstractmethod
    def rule_count(self) -> int:
        """Number of rules currently loaded."""
