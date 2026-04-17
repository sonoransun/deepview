"""Windows kernel crash-dump format parser.

Supports both 32-bit ``PAGE``/``DUMP`` and 64-bit ``PAGEDU64`` crash dumps.
The three standard ``DumpType`` flavours are all handled:

* ``FULL_DUMP`` (1) — the physical-memory-block buffer in the header lists
  contiguous page runs covering every page of RAM.
* ``KERNEL_DUMP`` (2) — identical structure to ``FULL_DUMP``, but only
  kernel-mode pages are written. We treat it the same as FULL for I/O; the
  runs themselves tell us which pages are actually present.
* ``BITMAP_DUMP`` (5) — a ``DMP\\0DUMP`` secondary header that carries a bitmap
  of which PFNs are present in the file.

The header is deliberately parsed in offset-addressable form (``_u32``/``_u64``
helpers rather than a single ``struct.unpack`` template) because the
Windows headers have different padding on different builds. We only extract
the fields we strictly need to address pages — DirectoryTableBase,
PfnDataBase, PsLoadedModuleList, KdDebuggerDataBlock, ContextRecord,
Exception, Comment, ..., are exposed on the instance but not interpreted.
"""
from __future__ import annotations

import mmap
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.exceptions import FormatError
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

# -- Magic --------------------------------------------------------------------
CRASHDUMP_MAGIC32 = b"PAGE"
CRASHDUMP_MAGIC64 = b"PAGEDU64"
VALID_DUMP32 = b"DUMP"
VALID_DUMP64 = b"DU64"

# DumpType
DUMP_TYPE_FULL = 1
DUMP_TYPE_KERNEL = 2
DUMP_TYPE_BITMAP = 5

# Header sizes per architecture
HEADER_SIZE_32 = 0x1000
HEADER_SIZE_64 = 0x2000

PAGE_SIZE = 0x1000

# -- 32-bit DUMP_HEADER offsets ----------------------------------------------
_H32_SIGNATURE = 0x000
_H32_VALID_DUMP = 0x004
_H32_MAJOR_VERSION = 0x008
_H32_MINOR_VERSION = 0x00C
_H32_DIRECTORY_TABLE_BASE = 0x010
_H32_PFN_DATABASE = 0x014
_H32_PS_LOADED_MODULE_LIST = 0x018
_H32_PS_ACTIVE_PROCESS_HEAD = 0x01C
_H32_MACHINE_IMAGE_TYPE = 0x020
_H32_NUMBER_PROCESSORS = 0x024
_H32_BUG_CHECK_CODE = 0x028
# BugCheckParameter1..4 = 0x02C..0x038
_H32_PHYSICAL_MEMORY_BLOCK = 0x064
_H32_DUMP_TYPE = 0xF88

# -- 64-bit DUMP_HEADER64 offsets --------------------------------------------
_H64_SIGNATURE = 0x000
_H64_VALID_DUMP = 0x004
_H64_MAJOR_VERSION = 0x008
_H64_MINOR_VERSION = 0x00C
_H64_DIRECTORY_TABLE_BASE = 0x010
_H64_PFN_DATABASE = 0x018
_H64_PS_LOADED_MODULE_LIST = 0x020
_H64_PS_ACTIVE_PROCESS_HEAD = 0x028
_H64_MACHINE_IMAGE_TYPE = 0x030
_H64_NUMBER_PROCESSORS = 0x034
_H64_BUG_CHECK_CODE = 0x038
# BugCheckParameter1..4 at 0x040..0x060 (8 bytes each)
_H64_PHYSICAL_MEMORY_BLOCK = 0x088
_H64_DUMP_TYPE = 0xF98

# -- Bitmap dump secondary header --------------------------------------------
# struct _BITMAP_DUMP {
#   uint32_t Signature;        // "SDMP"
#   uint32_t ValidDump;        // "DUMP"
#   uint64_t _reserved;
#   uint64_t FirstPage;        // file offset of first bitmapped page
#   uint64_t TotalPresentPages;
#   uint64_t Pages;            // bit count in the bitmap
#   uint8_t  Bitmap[Pages/8];
# };
_BITMAP_HEADER_FMT = "<4s4sQQQQ"
_BITMAP_HEADER_SIZE = struct.calcsize(_BITMAP_HEADER_FMT)


@dataclass
class _Run:
    """A contiguous page run in the physical memory block."""

    base_page: int
    page_count: int
    file_offset: int  # where the first byte of this run lives in the file


class CrashDumpLayer(DataLayer):
    """Windows kernel crash dump (``.dmp``) memory layer."""

    def __init__(self, path: Path, name: str = "") -> None:
        self._path = path
        self._name = name or "crashdump"
        self._size = path.stat().st_size
        self._file = open(path, "rb")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

        self._is_64bit = False
        self._header_size = HEADER_SIZE_32
        self._dump_type = 0
        self._major_version = 0
        self._minor_version = 0
        self._machine_image_type = 0
        self._number_processors = 0
        self._bug_check_code = 0
        self._directory_table_base = 0
        self._runs: list[_Run] = []
        self._total_pages = 0

        # BITMAP-only fields
        self._bitmap: bytes | None = None
        self._bitmap_first_page_offset = 0

        self._validate_magic()
        if self._is_64bit:
            self._parse_header64()
        else:
            self._parse_header32()

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def _validate_magic(self) -> None:
        if self._size < 8:
            raise FormatError("Crash dump file too small")
        head = bytes(self._mmap[:8])
        if head[:8] == CRASHDUMP_MAGIC64:
            self._is_64bit = True
            self._header_size = HEADER_SIZE_64
        elif head[:4] == CRASHDUMP_MAGIC32:
            self._is_64bit = False
            self._header_size = HEADER_SIZE_32
        else:
            raise FormatError(f"Not a valid Windows crash dump (magic: {head!r})")

    def _u32(self, offset: int) -> int:
        return int(struct.unpack_from("<I", self._mmap, offset)[0])

    def _u64(self, offset: int) -> int:
        return int(struct.unpack_from("<Q", self._mmap, offset)[0])

    # ---- 32-bit header ----

    def _parse_header32(self) -> None:
        self._major_version = self._u32(_H32_MAJOR_VERSION)
        self._minor_version = self._u32(_H32_MINOR_VERSION)
        self._directory_table_base = self._u32(_H32_DIRECTORY_TABLE_BASE)
        self._machine_image_type = self._u32(_H32_MACHINE_IMAGE_TYPE)
        self._number_processors = self._u32(_H32_NUMBER_PROCESSORS)
        self._bug_check_code = self._u32(_H32_BUG_CHECK_CODE)
        self._dump_type = self._u32(_H32_DUMP_TYPE)

        if self._dump_type == DUMP_TYPE_BITMAP:
            self._parse_bitmap_header()
        else:
            # 32-bit physical memory block: NumberOfRuns[4] NumberOfPages[4]
            # Run[NumberOfRuns] = (BasePage[4], PageCount[4])
            pmb = _H32_PHYSICAL_MEMORY_BLOCK
            if pmb + 8 > self._size:
                return
            number_of_runs = self._u32(pmb)
            number_of_pages = self._u32(pmb + 4)
            self._total_pages = number_of_pages
            cursor = self._header_size
            runs_off = pmb + 8
            for i in range(min(number_of_runs, 4096)):
                off = runs_off + i * 8
                if off + 8 > self._size:
                    break
                base_page = self._u32(off)
                page_count = self._u32(off + 4)
                self._runs.append(_Run(base_page, page_count, cursor))
                cursor += page_count * PAGE_SIZE

    # ---- 64-bit header ----

    def _parse_header64(self) -> None:
        self._major_version = self._u32(_H64_MAJOR_VERSION)
        self._minor_version = self._u32(_H64_MINOR_VERSION)
        self._directory_table_base = self._u64(_H64_DIRECTORY_TABLE_BASE)
        self._machine_image_type = self._u32(_H64_MACHINE_IMAGE_TYPE)
        self._number_processors = self._u32(_H64_NUMBER_PROCESSORS)
        self._bug_check_code = self._u32(_H64_BUG_CHECK_CODE)
        self._dump_type = self._u32(_H64_DUMP_TYPE)

        if self._dump_type == DUMP_TYPE_BITMAP:
            self._parse_bitmap_header()
        else:
            # 64-bit physical memory block: NumberOfRuns[4] NumberOfPages[4]
            # Run[NumberOfRuns] = (BasePage[8], PageCount[8])
            pmb = _H64_PHYSICAL_MEMORY_BLOCK
            if pmb + 8 > self._size:
                return
            number_of_runs = self._u32(pmb)
            number_of_pages = self._u32(pmb + 4)
            self._total_pages = number_of_pages
            cursor = self._header_size
            runs_off = pmb + 8
            for i in range(min(number_of_runs, 4096)):
                off = runs_off + i * 16
                if off + 16 > self._size:
                    break
                base_page = self._u64(off)
                page_count = self._u64(off + 8)
                self._runs.append(_Run(base_page, page_count, cursor))
                cursor += page_count * PAGE_SIZE

    # ---- Bitmap dump ----

    def _parse_bitmap_header(self) -> None:
        """Parse the _BITMAP_DUMP header that follows the main DUMP_HEADER."""
        off = self._header_size
        if off + _BITMAP_HEADER_SIZE > self._size:
            return
        sig, valid, _reserved, first_page, present, pages = struct.unpack_from(
            _BITMAP_HEADER_FMT, self._mmap, off
        )
        # Signature is commonly "SDMP" in the wild; we accept any 4-byte tag
        # beginning with "DMP" or the literal "SDMP" to be lenient.
        if sig not in (b"SDMP", b"DMPB", b"DMP\x00"):
            # Still try to proceed — some builds use other tags.
            pass
        if valid != b"DUMP":
            # Non-fatal: we simply won't have a bitmap.
            return
        bitmap_off = off + _BITMAP_HEADER_SIZE
        bitmap_bytes = (pages + 7) // 8
        end = bitmap_off + bitmap_bytes
        if end > self._size or pages == 0:
            return

        self._bitmap = bytes(self._mmap[bitmap_off:end])
        self._bitmap_first_page_offset = int(first_page)
        self._total_pages = int(pages)

        # Materialize the bitmap as a list of runs so read() can reuse the
        # same lookup path as FULL / KERNEL dumps.
        self._runs = self._runs_from_bitmap(self._bitmap, int(pages), int(first_page))

    @staticmethod
    def _runs_from_bitmap(bitmap: bytes, total_pages: int, first_page_offset: int) -> list[_Run]:
        runs: list[_Run] = []
        present_index = 0
        i = 0
        while i < total_pages:
            byte = bitmap[i >> 3]
            if byte == 0:
                # Fast skip of fully-empty bytes.
                i = (i + 8) & ~7
                continue
            if (byte >> (i & 7)) & 1:
                start = i
                while i < total_pages and (bitmap[i >> 3] >> (i & 7)) & 1:
                    i += 1
                count = i - start
                file_off = first_page_offset + present_index * PAGE_SIZE
                runs.append(_Run(start, count, file_off))
                present_index += count
            else:
                i += 1
        return runs

    # ------------------------------------------------------------------
    # Run lookup
    # ------------------------------------------------------------------

    def _find_run(self, pfn: int) -> _Run | None:
        # Linear scan; number of runs is small in practice (<4096).
        for run in self._runs:
            if run.base_page <= pfn < run.base_page + run.page_count:
                return run
        return None

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        if length <= 0:
            return b""
        if offset < 0:
            return b"\x00" * length if pad else b""

        result = bytearray()
        remaining = length
        cur = offset
        while remaining > 0:
            pfn = cur // PAGE_SIZE
            intra = cur % PAGE_SIZE
            run = self._find_run(pfn)
            if run is None:
                if pad:
                    chunk = min(remaining, PAGE_SIZE - intra)
                    result.extend(b"\x00" * chunk)
                    remaining -= chunk
                    cur += chunk
                    continue
                break
            run_pfn_off = pfn - run.base_page
            available_pages = run.page_count - run_pfn_off
            available_bytes = available_pages * PAGE_SIZE - intra
            take = min(remaining, available_bytes)
            file_off = run.file_offset + run_pfn_off * PAGE_SIZE + intra
            end = min(file_off + take, self._size)
            if file_off >= self._size:
                if pad:
                    result.extend(b"\x00" * take)
                    remaining -= take
                    cur += take
                    continue
                break
            chunk_bytes = bytes(self._mmap[file_off:end])
            result.extend(chunk_bytes)
            if pad and len(chunk_bytes) < take:
                # File truncated mid-run — zero-fill the remainder.
                result.extend(b"\x00" * (take - len(chunk_bytes)))
            remaining -= take
            cur += take
        if pad and len(result) < length:
            result.extend(b"\x00" * (length - len(result)))
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("Crash dump layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length <= 0:
            return False
        start_pfn = offset // PAGE_SIZE
        end_pfn = (offset + length - 1) // PAGE_SIZE
        return all(self._find_run(p) is not None for p in range(start_pfn, end_pfn + 1))

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        if self._total_pages > 0:
            return self._total_pages * PAGE_SIZE - 1
        if self._runs:
            last = self._runs[-1]
            return (last.base_page + last.page_count) * PAGE_SIZE - 1
        return max(self._size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            os="windows",
            arch="x64" if self._is_64bit else "x86",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        chunk_size = 4 * 1024 * 1024
        total = self.maximum_address + 1
        scanned = 0
        for run in self._runs:
            run_size = run.page_count * PAGE_SIZE
            inner = 0
            while inner < run_size:
                read_size = min(chunk_size, run_size - inner)
                file_off = run.file_offset + inner
                end = min(file_off + read_size, self._size)
                if file_off >= self._size:
                    break
                chunk = bytes(self._mmap[file_off:end])
                virt_offset = run.base_page * PAGE_SIZE + inner
                for result in scanner.scan(chunk, offset=virt_offset):
                    yield result
                inner += len(chunk)
                scanned += len(chunk)
                if progress_callback and total > 0:
                    progress_callback(min(scanned / total, 1.0))
                if len(chunk) < read_size:
                    break

    # ------------------------------------------------------------------
    # Introspection helpers (not part of the ABC)
    # ------------------------------------------------------------------

    @property
    def is_64bit(self) -> bool:
        return self._is_64bit

    @property
    def dump_type(self) -> int:
        return self._dump_type

    @property
    def directory_table_base(self) -> int:
        return self._directory_table_base

    @property
    def runs(self) -> list[_Run]:
        return list(self._runs)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        try:
            if self._mmap is not None:
                self._mmap.close()
        except (ValueError, BufferError):
            pass
        self._mmap = None  # type: ignore[assignment]
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None  # type: ignore[assignment]

    def __enter__(self) -> CrashDumpLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
