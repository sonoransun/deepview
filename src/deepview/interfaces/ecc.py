from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class ECCResult:
    """Outcome of decoding a single ECC-protected payload."""

    data: bytes
    errors_corrected: int
    uncorrectable: bool


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
