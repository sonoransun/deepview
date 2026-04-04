"""LiME memory dump format parser."""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from deepview.core.types import LayerMetadata, ScanResult
from deepview.core.exceptions import FormatError
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

LIME_MAGIC = 0x4C694D45
LIME_HEADER_SIZE = 32  # 4+4+8+8+8
LIME_HEADER_FMT = "<IIqqq"  # magic, version, start, end, reserved


@dataclass
class LiMERange:
    """A contiguous memory range in a LiME dump."""

    start: int
    end: int
    file_offset: int  # where the data starts in the file (after header)


class LiMEMemoryLayer(DataLayer):
    """LiME format memory dump layer."""

    def __init__(self, path: Path, name: str = ""):
        self._path = path
        self._name = name or path.name
        self._ranges: list[LiMERange] = []
        self._file = open(path, "rb")
        self._parse_headers()

    def _parse_headers(self) -> None:
        """Parse all LiME range headers."""
        self._file.seek(0)
        while True:
            header_data = self._file.read(LIME_HEADER_SIZE)
            if len(header_data) < LIME_HEADER_SIZE:
                break

            magic, version, start, end, reserved = struct.unpack(LIME_HEADER_FMT, header_data)
            if magic != LIME_MAGIC:
                raise FormatError(f"Invalid LiME magic: {magic:#x} (expected {LIME_MAGIC:#x})")

            data_offset = self._file.tell()
            data_size = end - start + 1
            self._ranges.append(LiMERange(start=start, end=end, file_offset=data_offset))

            # Skip to next header
            self._file.seek(data_size, 1)

        if not self._ranges:
            raise FormatError("No valid LiME ranges found")

    def _find_range(self, offset: int) -> LiMERange | None:
        """Find the range containing the given physical address."""
        for r in self._ranges:
            if r.start <= offset <= r.end:
                return r
        return None

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        result = bytearray()
        remaining = length
        current = offset

        while remaining > 0:
            r = self._find_range(current)
            if r is None:
                if pad:
                    # Find next range to know how much to pad
                    next_start = None
                    for rng in self._ranges:
                        if rng.start > current:
                            if next_start is None or rng.start < next_start:
                                next_start = rng.start
                    if next_start is not None and next_start < current + remaining:
                        gap = next_start - current
                        result.extend(b"\x00" * gap)
                        remaining -= gap
                        current = next_start
                        continue
                    result.extend(b"\x00" * remaining)
                break

            range_offset = current - r.start
            available = r.end - current + 1
            to_read = min(remaining, available)

            self._file.seek(r.file_offset + range_offset)
            data = self._file.read(to_read)
            result.extend(data)

            remaining -= len(data)
            current += len(data)

        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("LiME layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self._find_range(offset) is not None

    @property
    def minimum_address(self) -> int:
        return self._ranges[0].start if self._ranges else 0

    @property
    def maximum_address(self) -> int:
        return self._ranges[-1].end if self._ranges else 0

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def ranges(self) -> list[LiMERange]:
        return list(self._ranges)

    def scan(self, scanner: PatternScanner, progress_callback: Callable | None = None) -> Iterator[ScanResult]:
        total_size = sum(r.end - r.start + 1 for r in self._ranges)
        scanned = 0
        chunk_size = 4 * 1024 * 1024  # 4 MiB
        overlap = 4096  # 4 KiB overlap to catch patterns at chunk boundaries
        for r in self._ranges:
            size = r.end - r.start + 1
            range_offset = 0
            while range_offset < size:
                read_size = min(chunk_size, size - range_offset)
                self._file.seek(r.file_offset + range_offset)
                chunk = self._file.read(read_size)
                for result in scanner.scan(chunk, offset=r.start + range_offset):
                    yield result
                if range_offset + read_size >= size:
                    break
                range_offset += read_size - overlap
            scanned += size
            if progress_callback:
                progress_callback(scanned / total_size)

    def close(self) -> None:
        if self._file:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
