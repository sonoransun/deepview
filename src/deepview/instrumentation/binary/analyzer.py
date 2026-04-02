"""LIEF-based binary analysis for PE/ELF/Mach-O."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger
from deepview.core.exceptions import InstrumentationError

log = get_logger("instrumentation.binary.analyzer")


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    size: int
    entropy: float = 0.0
    characteristics: str = ""


@dataclass
class ImportInfo:
    library: str
    function: str
    address: int = 0


@dataclass
class ExportInfo:
    name: str
    address: int
    ordinal: int = 0


@dataclass
class FunctionInfo:
    name: str
    address: int
    size: int = 0
    module: str = ""


class BinaryAnalyzer:
    """Analyze PE/ELF/Mach-O binaries using LIEF."""

    def __init__(self, path: Path):
        self._path = path
        self._binary = None
        self._available = False

        try:
            import lief
            self._lief = lief
            self._binary = lief.parse(str(path))
            if self._binary is None:
                raise InstrumentationError(f"Failed to parse binary: {path}")
            self._available = True
        except ImportError:
            log.debug("lief_not_installed")

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def format(self) -> str:
        if not self._available:
            return "unknown"
        if self._lief.is_elf(str(self._path)):
            return "ELF"
        elif self._lief.is_pe(str(self._path)):
            return "PE"
        elif self._lief.is_macho(str(self._path)):
            return "MachO"
        return "unknown"

    @property
    def arch(self) -> str:
        if not self._available or not self._binary:
            return "unknown"
        header = self._binary.header
        if hasattr(header, 'machine_type'):
            mt = str(header.machine_type)
            if "x86_64" in mt or "AMD64" in mt:
                return "x86_64"
            elif "AARCH64" in mt or "ARM64" in mt:
                return "aarch64"
            elif "386" in mt or "x86" in mt.lower():
                return "x86"
        return "unknown"

    @property
    def is_pie(self) -> bool:
        if not self._available or not self._binary:
            return False
        if hasattr(self._binary, 'is_pie'):
            return self._binary.is_pie
        return False

    @property
    def sections(self) -> list[SectionInfo]:
        if not self._available or not self._binary:
            return []
        result = []
        for section in self._binary.sections:
            result.append(SectionInfo(
                name=section.name,
                virtual_address=section.virtual_address,
                size=section.size,
                entropy=section.entropy if hasattr(section, 'entropy') else 0.0,
            ))
        return result

    @property
    def imports(self) -> list[ImportInfo]:
        if not self._available or not self._binary:
            return []
        result = []
        if hasattr(self._binary, 'imports') and self._binary.imports:
            for imp in self._binary.imports:
                if hasattr(imp, 'entries'):
                    for entry in imp.entries:
                        result.append(ImportInfo(
                            library=imp.name if hasattr(imp, 'name') else "",
                            function=entry.name if hasattr(entry, 'name') else "",
                            address=entry.iat_address if hasattr(entry, 'iat_address') else 0,
                        ))
                elif hasattr(imp, 'name'):
                    result.append(ImportInfo(library="", function=imp.name, address=0))
        return result

    @property
    def exports(self) -> list[ExportInfo]:
        if not self._available or not self._binary:
            return []
        result = []
        if hasattr(self._binary, 'exported_functions'):
            for func in self._binary.exported_functions:
                result.append(ExportInfo(
                    name=func.name if hasattr(func, 'name') else str(func),
                    address=func.address if hasattr(func, 'address') else 0,
                ))
        return result

    @property
    def symbols(self) -> list[FunctionInfo]:
        if not self._available or not self._binary:
            return []
        result = []
        if hasattr(self._binary, 'symbols'):
            for sym in self._binary.symbols:
                if hasattr(sym, 'is_function') and sym.is_function:
                    result.append(FunctionInfo(
                        name=sym.name,
                        address=sym.value if hasattr(sym, 'value') else 0,
                        size=sym.size if hasattr(sym, 'size') else 0,
                    ))
        return result

    def find_function(self, name: str) -> FunctionInfo | None:
        """Find a function by name in exports, then symbols."""
        for exp in self.exports:
            if exp.name == name:
                return FunctionInfo(name=exp.name, address=exp.address)
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    def get_bytes_at(self, virtual_address: int, size: int) -> bytes:
        """Read bytes from the binary at a virtual address."""
        if not self._available or not self._binary:
            return b""
        content = self._binary.get_content_from_virtual_address(virtual_address, size)
        return bytes(content)

    def summary(self) -> dict:
        """Return a summary of the binary."""
        return {
            "path": str(self._path),
            "format": self.format,
            "arch": self.arch,
            "pie": self.is_pie,
            "sections": len(self.sections),
            "imports": len(self.imports),
            "exports": len(self.exports),
            "symbols": len(self.symbols),
        }
