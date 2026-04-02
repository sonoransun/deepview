"""Raw memory dump format with mmap-based I/O."""
from __future__ import annotations

import mmap
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class RawMemoryLayer(DataLayer):
    """Raw flat memory dump. The file is a byte-for-byte image of physical memory."""

    def __init__(self, path: Path, name: str = ""):
        self._path = path
        self._name = name or path.name
        self._size = path.stat().st_size
        self._file = open(path, "r+b" if path.stat().st_size > 0 else "rb")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        if offset < 0 or offset >= self._size:
            if pad:
                return b"\x00" * length
            return b""
        end = min(offset + length, self._size)
        data = self._mmap[offset:end]
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("Raw layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= self._size

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return self._size

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=0,
            maximum_address=self._size,
        )

    def scan(self, scanner: PatternScanner, progress_callback: Callable | None = None) -> Iterator[ScanResult]:
        chunk_size = 4 * 1024 * 1024  # 4 MiB chunks
        overlap = 4096  # overlap to catch patterns at boundaries
        offset = 0
        while offset < self._size:
            end = min(offset + chunk_size, self._size)
            chunk = self._mmap[offset:end]
            for result in scanner.scan(chunk, offset=offset):
                yield result
            if progress_callback:
                progress_callback(end / self._size)
            offset = end - overlap if end < self._size else end

    def close(self) -> None:
        if self._mmap:
            self._mmap.close()
        if self._file:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
