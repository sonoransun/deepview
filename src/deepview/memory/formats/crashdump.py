"""Windows crash dump format parser (stub)."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from deepview.core.types import LayerMetadata, ScanResult
from deepview.core.exceptions import FormatError
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

# Windows crash dump signatures
CRASHDUMP_MAGIC32 = b"PAGE"
CRASHDUMP_MAGIC64 = b"PAGEDU64"


class CrashDumpLayer(DataLayer):
    """Windows crash dump (.dmp) memory layer.

    Supports both 32-bit and 64-bit full memory dumps.
    For complete implementation, delegates to Volatility 3's crash dump layer.
    """

    def __init__(self, path: Path, name: str = ""):
        self._path = path
        self._name = name or path.name
        self._file = open(path, "rb")
        self._validate()
        self._size = path.stat().st_size

    def _validate(self) -> None:
        self._file.seek(0)
        magic = self._file.read(8)
        if not (magic[:4] == CRASHDUMP_MAGIC32 or magic[:8] == CRASHDUMP_MAGIC64):
            raise FormatError("Not a valid Windows crash dump file")

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        # Simplified: treat as raw after header for basic access
        # Full implementation should parse dump header and page runs
        header_size = 4096  # Standard page size header
        file_offset = header_size + offset
        if file_offset >= self._size:
            return b"\x00" * length if pad else b""
        self._file.seek(file_offset)
        data = self._file.read(length)
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("Crash dump layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset < self._size - 4096

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return self._size - 4096

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name, minimum_address=0, maximum_address=self.maximum_address)

    def scan(self, scanner: PatternScanner, progress_callback: Callable | None = None) -> Iterator[ScanResult]:
        chunk_size = 4 * 1024 * 1024
        offset = 0
        total = self.maximum_address
        while offset < total:
            data = self.read(offset, chunk_size)
            if not data:
                break
            for result in scanner.scan(data, offset=offset):
                yield result
            offset += len(data)
            if progress_callback:
                progress_callback(offset / total if total > 0 else 1.0)

    def close(self) -> None:
        if self._file:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
