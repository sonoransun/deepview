"""Instrumentation point discovery in binaries."""
from __future__ import annotations
from dataclasses import dataclass
from deepview.core.logging import get_logger
from deepview.instrumentation.binary.analyzer import BinaryAnalyzer

log = get_logger("instrumentation.binary.points")

SECURITY_SENSITIVE = [
    "malloc", "free", "realloc", "calloc",
    "open", "read", "write", "close", "openat",
    "connect", "send", "recv", "bind", "listen", "accept",
    "execve", "execvp", "system", "popen", "fork", "clone",
    "dlopen", "dlsym",
    "mmap", "mprotect", "munmap",
    "socket", "sendto", "recvfrom",
    "getenv", "setenv",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "CreateProcessA", "CreateProcessW",
    "CreateRemoteThread", "WriteProcessMemory",
    "RegOpenKeyExA", "RegOpenKeyExW",
]


@dataclass
class InstrumentationPoint:
    name: str
    address: int
    point_type: str  # "export", "import", "symbol", "prologue"
    module: str = ""
    size: int = 0
    hookable: bool = True


class InstrumentationPointFinder:
    """Discover candidate instrumentation points in a binary."""

    def __init__(self, binary: BinaryAnalyzer):
        self._binary = binary

    def find_all(self) -> list[InstrumentationPoint]:
        """Find all instrumentable points."""
        points = {}
        for pt in self.find_exports():
            points[pt.name] = pt
        for pt in self.find_imports():
            if pt.name not in points:
                points[pt.name] = pt
        for pt in self.find_security_sensitive():
            if pt.name not in points:
                points[pt.name] = pt
        return list(points.values())

    def find_exports(self) -> list[InstrumentationPoint]:
        result = []
        for exp in self._binary.exports:
            if exp.address > 0:
                result.append(InstrumentationPoint(
                    name=exp.name,
                    address=exp.address,
                    point_type="export",
                ))
        return result

    def find_imports(self) -> list[InstrumentationPoint]:
        result = []
        for imp in self._binary.imports:
            if imp.function:
                result.append(InstrumentationPoint(
                    name=imp.function,
                    address=imp.address,
                    point_type="import",
                    module=imp.library,
                ))
        return result

    def find_security_sensitive(self) -> list[InstrumentationPoint]:
        """Find security-sensitive functions that should be monitored."""
        result = []
        all_names = set()

        for exp in self._binary.exports:
            all_names.add(exp.name)
        for imp in self._binary.imports:
            all_names.add(imp.function)
        for sym in self._binary.symbols:
            all_names.add(sym.name)

        for sensitive in SECURITY_SENSITIVE:
            if sensitive in all_names:
                func = self._binary.find_function(sensitive)
                if func:
                    result.append(InstrumentationPoint(
                        name=func.name,
                        address=func.address,
                        point_type="security_sensitive",
                        size=func.size,
                    ))
        return result

    def find_by_pattern(self, pattern: str) -> list[InstrumentationPoint]:
        """Find functions matching a glob pattern."""
        import fnmatch
        result = []
        for sym in self._binary.symbols:
            if fnmatch.fnmatch(sym.name, pattern):
                result.append(InstrumentationPoint(
                    name=sym.name,
                    address=sym.address,
                    point_type="symbol",
                    size=sym.size,
                ))
        return result
