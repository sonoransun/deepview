"""Abstract interface for disassembly and reverse-engineering backends."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class DisassemblyEngine(ABC):
    """Abstract wrapper around a disassembly/reverse-engineering backend
    (e.g. Ghidra, Hopper, Capstone)."""

    @abstractmethod
    def open_binary(self, path: Path) -> DisassemblySession:
        """Open a binary for analysis and return a session handle."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` when the underlying engine is installed and usable."""

    @classmethod
    @abstractmethod
    def engine_name(cls) -> str:
        """Human-readable name for this disassembly engine."""

    @classmethod
    @abstractmethod
    def supported_capabilities(cls) -> set[str]:
        """Return set of capability strings this engine supports.

        Standard capabilities: ``disassemble``, ``decompile``, ``cfg``,
        ``xrefs``, ``functions``, ``strings``, ``data_types``, ``signatures``.
        """


class DisassemblySession(ABC):
    """An open analysis session on a single binary."""

    @abstractmethod
    def disassemble(self, address: int, count: int = 20) -> list[dict[str, Any]]:
        """Disassemble *count* instructions starting at *address*."""

    @abstractmethod
    def disassemble_function(self, name_or_address: str | int) -> list[dict[str, Any]]:
        """Disassemble an entire function by name or start address."""

    @abstractmethod
    def decompile(self, name_or_address: str | int) -> str:
        """Decompile a function to pseudo-C source."""

    @abstractmethod
    def functions(self) -> list[dict[str, Any]]:
        """List all identified functions in the binary."""

    @abstractmethod
    def xrefs_to(self, address: int) -> list[dict[str, Any]]:
        """Return cross-references *to* the given address."""

    @abstractmethod
    def xrefs_from(self, address: int) -> list[dict[str, Any]]:
        """Return cross-references *from* the given address."""

    @abstractmethod
    def cfg(self, name_or_address: str | int) -> dict[str, Any]:
        """Return the control-flow graph for a function."""

    @abstractmethod
    def strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        """Extract strings from the binary."""

    @abstractmethod
    def close(self) -> None:
        """Release resources held by this session."""

    @property
    @abstractmethod
    def binary_info(self) -> dict[str, Any]:
        """Summary information: format, architecture, entry point, sections."""
