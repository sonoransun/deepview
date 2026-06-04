from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ECCResult:
    """Outcome of decoding a single ECC-protected payload."""

    data: bytes
    errors_corrected: int
    uncorrectable: bool

    def __post_init__(self) -> None:
        # Guard the two invariants every decoder upholds: a non-negative
        # error count, and that an uncorrectable codeword cannot
        # simultaneously claim corrected errors. ``ECCDataLayer`` accumulates
        # ``errors_corrected`` only on the corrected branch, so a
        # contradictory result would silently skew its error statistics.
        if self.errors_corrected < 0:
            raise ValueError(
                f"errors_corrected must be >= 0, got {self.errors_corrected}"
            )
        if self.uncorrectable and self.errors_corrected != 0:
            raise ValueError(
                "uncorrectable result cannot also report corrected errors "
                f"(errors_corrected={self.errors_corrected})"
            )

    @property
    def ok(self) -> bool:
        """True when the payload decoded to usable bytes (correctable)."""
        return not self.uncorrectable


class ECCDecoder(ABC):
    """Stateless error-correcting code decoder (NAND/eMMC style)."""

    name: str = ""
    data_chunk: int = 0
    ecc_bytes: int = 0

    @abstractmethod
    def decode(self, data: bytes, ecc: bytes) -> ECCResult:
        """Decode *data* using parity *ecc*; return corrected data + stats."""

    def encode(self, data: bytes) -> bytes:
        """Optional inverse, used only by tests. Default raises NotImplementedError."""
        raise NotImplementedError(f"{type(self).__name__} does not implement encode()")
