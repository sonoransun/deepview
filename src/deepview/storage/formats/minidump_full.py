"""Windows minidump (``.dmp``) memory layer, ``Memory64ListStream`` path.

Full minidumps (``MiniDumpWithFullMemory``) store the guest's physical-address
space as a list of contiguous ranges described by a
``MINIDUMP_MEMORY64_LIST`` stream. Each descriptor is an
``(StartOfMemoryRange, DataSize)`` pair; the actual bytes live at a single
``BaseRva`` offset that the descriptor array indexes sequentially. We parse
``MINIDUMP_HEADER`` + the stream directory, locate the Memory64 list, build
an in-memory run table, and service :meth:`read` by binary search.
"""
from __future__ import annotations

import bisect
import mmap
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.exceptions import FormatError
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


_MDMP_SIGNATURE = 0x504D444D  # b"MDMP" little-endian

# MINIDUMP_HEADER (32 bytes):
#   DWORD Signature
#   DWORD Version           (low = MINIDUMP_VERSION, high = implementation)
#   DWORD NumberOfStreams
#   RVA   StreamDirectoryRva
#   DWORD CheckSum
#   DWORD TimeDateStamp
#   ULONG64 Flags
_MDMP_HEADER_FMT = "<IIIIIIQ"
_MDMP_HEADER_SIZE = struct.calcsize(_MDMP_HEADER_FMT)

# MINIDUMP_DIRECTORY (12 bytes): DWORD StreamType; MINIDUMP_LOCATION_DESCRIPTOR
# (DWORD DataSize, RVA Rva).
_MDMP_DIR_FMT = "<III"
_MDMP_DIR_SIZE = struct.calcsize(_MDMP_DIR_FMT)

# Stream type for Memory64ListStream.
_MEMORY64_LIST_STREAM = 9

# MINIDUMP_MEMORY64_LIST header (16 bytes): ULONG64 NumberOfMemoryRanges,
# RVA64 BaseRva.
_MEM64_LIST_HEADER_FMT = "<QQ"
_MEM64_LIST_HEADER_SIZE = struct.calcsize(_MEM64_LIST_HEADER_FMT)

# MINIDUMP_MEMORY_DESCRIPTOR64 (16 bytes): ULONG64 StartOfMemoryRange,
# ULONG64 DataSize.
_MEM64_DESCRIPTOR_FMT = "<QQ"
_MEM64_DESCRIPTOR_SIZE = struct.calcsize(_MEM64_DESCRIPTOR_FMT)


@dataclass(frozen=True)
class Memory64Run:
    """One contiguous memory range in a full minidump."""

    virtual_address: int
    file_offset: int
    size: int


class MinidumpFullLayer(DataLayer):
    """Full (``Memory64ListStream``) minidump as a ``DataLayer``."""

    def __init__(self, path: Path, name: str = "") -> None:
        self._path = path
        self._name = name or "minidump_full"
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

        self._runs: list[Memory64Run] = []
        # Parallel sorted keys for binary search over virtual addresses.
        self._run_starts: list[int] = []
        self._parse()

    # ------------------------------------------------------------------
    # Header / stream parsing
    # ------------------------------------------------------------------

    def _parse(self) -> None:
        if self._mmap is None or self._size < _MDMP_HEADER_SIZE:
            raise FormatError("Minidump file is too small to contain a header")
        header = bytes(self._mmap[0:_MDMP_HEADER_SIZE])
        (
            signature,
            _version,
            number_of_streams,
            stream_directory_rva,
            _checksum,
            _time_date_stamp,
            _flags,
        ) = struct.unpack(_MDMP_HEADER_FMT, header)
        if signature != _MDMP_SIGNATURE:
            raise FormatError(
                f"Not a minidump file (bad signature: {signature:#010x})"
            )
        if number_of_streams == 0:
            return
        dir_end = stream_directory_rva + number_of_streams * _MDMP_DIR_SIZE
        if dir_end > self._size:
            raise FormatError("Minidump stream directory extends past EOF")

        mem64_rva = None
        mem64_size = None
        for i in range(number_of_streams):
            entry_off = stream_directory_rva + i * _MDMP_DIR_SIZE
            stream_type, data_size, rva = struct.unpack_from(
                _MDMP_DIR_FMT, self._mmap, entry_off
            )
            if stream_type == _MEMORY64_LIST_STREAM:
                mem64_rva = rva
                mem64_size = data_size
                break
        if mem64_rva is None or mem64_size is None:
            # No full-memory stream; leave run table empty. Reads will return
            # empty / zero-padded — the layer is still technically valid.
            return

        if mem64_rva + _MEM64_LIST_HEADER_SIZE > self._size:
            raise FormatError("Memory64 list header extends past EOF")
        number_of_ranges, base_rva = struct.unpack_from(
            _MEM64_LIST_HEADER_FMT, self._mmap, mem64_rva
        )
        desc_start = mem64_rva + _MEM64_LIST_HEADER_SIZE
        desc_end = desc_start + number_of_ranges * _MEM64_DESCRIPTOR_SIZE
        if desc_end > self._size:
            raise FormatError(
                "Memory64 descriptor array extends past EOF"
            )

        cursor = base_rva
        runs: list[Memory64Run] = []
        for i in range(number_of_ranges):
            off = desc_start + i * _MEM64_DESCRIPTOR_SIZE
            start, data_size = struct.unpack_from(
                _MEM64_DESCRIPTOR_FMT, self._mmap, off
            )
            if data_size == 0:
                continue
            if cursor + data_size > self._size:
                raise FormatError(
                    f"Minidump run {i} extends past EOF "
                    f"(file_offset={cursor}, size={data_size}, "
                    f"file_size={self._size})"
                )
            runs.append(
                Memory64Run(
                    virtual_address=start,
                    file_offset=cursor,
                    size=data_size,
                )
            )
            cursor += data_size

        # Keep runs sorted by virtual address for bisect-based lookup.
        runs.sort(key=lambda r: r.virtual_address)
        self._runs = runs
        self._run_starts = [r.virtual_address for r in runs]

    def _find_run(self, virtual_address: int) -> Memory64Run | None:
        if not self._runs:
            return None
        idx = bisect.bisect_right(self._run_starts, virtual_address) - 1
        if idx < 0:
            return None
        run = self._runs[idx]
        if run.virtual_address <= virtual_address < run.virtual_address + run.size:
            return run
        return None

    def _next_run_start(self, virtual_address: int) -> int | None:
        idx = bisect.bisect_right(self._run_starts, virtual_address)
        if idx >= len(self._run_starts):
            return None
        return self._run_starts[idx]

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if self._mmap is None or not self._runs:
            return b"\x00" * length if pad else b""
        out = bytearray()
        current = offset
        remaining = length
        while remaining > 0:
            run = self._find_run(current)
            if run is None:
                if not pad:
                    if out:
                        return bytes(out)
                    return b""
                nxt = self._next_run_start(current)
                gap = (
                    min(nxt - current, remaining) if nxt is not None else remaining
                )
                out.extend(b"\x00" * gap)
                current += gap
                remaining -= gap
                continue
            local = current - run.virtual_address
            available = run.size - local
            take = min(remaining, available)
            file_start = run.file_offset + local
            file_end = file_start + take
            out.extend(bytes(self._mmap[file_start:file_end]))
            current += take
            remaining -= take
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("MinidumpFullLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        if length == 0:
            return True
        end = offset + length
        cur = offset
        while cur < end:
            run = self._find_run(cur)
            if run is None:
                return False
            cur = min(end, run.virtual_address + run.size)
        return True

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        if self._mmap is None or not self._runs:
            return
        total = sum(r.size for r in self._runs)
        scanned = 0
        chunk_size = 4 * 1024 * 1024
        overlap = 4096
        for run in self._runs:
            pos = 0
            while pos < run.size:
                read_size = min(chunk_size, run.size - pos)
                file_start = run.file_offset + pos
                file_end = file_start + read_size
                chunk = bytes(self._mmap[file_start:file_end])
                for result in scanner.scan(
                    chunk, offset=run.virtual_address + pos
                ):
                    yield result
                if pos + read_size >= run.size:
                    break
                pos += read_size - overlap
            scanned += run.size
            if progress_callback is not None and total > 0:
                progress_callback(scanned / total)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def minimum_address(self) -> int:
        if not self._runs:
            return 0
        return self._runs[0].virtual_address

    @property
    def maximum_address(self) -> int:
        if not self._runs:
            return 0
        last = self._runs[-1]
        return last.virtual_address + last.size - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def runs(self) -> list[Memory64Run]:
        return list(self._runs)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._mmap is not None:
            try:
                self._mmap.close()
            except ValueError:
                pass
            self._mmap = None
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def __enter__(self) -> MinidumpFullLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
