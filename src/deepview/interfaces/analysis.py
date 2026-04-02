from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from deepview.interfaces.layer import DataLayer


class AnalysisEngine(ABC):
    """Abstract wrapper around a memory-forensics analysis backend
    (e.g. Volatility 3, Rekall)."""

    @abstractmethod
    def open_image(self, path: Path) -> DataLayer:
        """Open a memory image at *path* and return a :class:`DataLayer`."""

    @abstractmethod
    def run_plugin(
        self,
        plugin_name: str,
        layer: DataLayer,
        **kwargs: Any,
    ) -> Any:
        """Execute the named plugin against *layer* and return its output."""

    @abstractmethod
    def list_plugins(self) -> list[str]:
        """Return every plugin name known to this engine."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` when the underlying engine is installed and usable."""

    @classmethod
    @abstractmethod
    def engine_name(cls) -> str:
        """Human-readable name for this analysis engine."""
