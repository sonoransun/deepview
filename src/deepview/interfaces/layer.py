from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class DataLayer(ABC):
    """Fundamental memory / data-source abstraction (modeled on Volatility 3)."""

    # ------------------------------------------------------------------
    # Abstract methods
    # ------------------------------------------------------------------

    @abstractmethod
    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        """Read *length* bytes starting at *offset*.

        If *pad* is ``True``, invalid regions are zero-filled instead of
        raising an exception.
        """

    @abstractmethod
    def write(self, offset: int, data: bytes) -> None:
        """Write *data* at the given *offset*."""

    @abstractmethod
    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Return ``True`` when the byte range is backed by real data."""

    @abstractmethod
    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        """Delegate a pattern scan across this layer to *scanner*."""

    # ------------------------------------------------------------------
    # Abstract properties
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def minimum_address(self) -> int:
        """Lowest valid address in this layer."""

    @property
    @abstractmethod
    def maximum_address(self) -> int:
        """Highest valid address in this layer."""

    @property
    @abstractmethod
    def metadata(self) -> LayerMetadata:
        """Descriptive metadata for this layer."""

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    def read_string(
        self,
        offset: int,
        max_length: int = 256,
        encoding: str = "utf-8",
    ) -> str:
        """Read bytes starting at *offset* until a null byte or *max_length*,
        then decode with *encoding*."""
        raw = self.read(offset, max_length, pad=True)
        null_pos = raw.find(b"\x00")
        if null_pos != -1:
            raw = raw[:null_pos]
        return raw.decode(encoding, errors="replace")
