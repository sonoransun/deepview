"""Hibernation file (hiberfil.sys) parser.

Windows stores a compressed snapshot of physical memory in
``C:\\hiberfil.sys`` when the machine hibernates. The file begins with a
``PO_MEMORY_IMAGE`` header whose exact layout has drifted between Windows
versions, but the fields we rely on (signature, page size, total-pages,
first-table-page) have been stable since Windows 7.

Each "memory table" in the chain (``_PO_MEMORY_RANGE_TABLE``) lists a set
of contiguous physical-page runs, and each run points at an Xpress or
Xpress-Huffman compressed block that expands to
``PageCount * PageSize`` bytes of physical memory.

Because the pure-Python ``deepview.storage.encodings.xpress`` decoder is
still partial (the Huffman branch raises ``NotImplementedError`` for
complex streams), the layer transparently degrades to a **raw pass-through
mode** when it cannot decode the tables: the file is exposed verbatim,
``compression_status == "undecoded"`` is recorded on the class instance,
and callers can still run pattern scans over the physical bytes.
"""
from __future__ import annotations

import mmap
import struct
from collections import OrderedDict
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.exceptions import FormatError
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

# -- Magic --------------------------------------------------------------------
HIBR_MAGIC_LOWER = b"hibr"
WAKE_MAGIC_LOWER = b"wake"
HIBR_MAGIC_UPPER = b"HIBR"
WAKE_MAGIC_UPPER = b"WAKE"
_VALID_MAGICS = (HIBR_MAGIC_LOWER, WAKE_MAGIC_LOWER, HIBR_MAGIC_UPPER, WAKE_MAGIC_UPPER)

# -- PO_MEMORY_IMAGE offsets (Windows 7 / 8 / 10 conservative layout) ---------
# These offsets are not bit-exact for every Windows build; they work for
# Windows 7+ with 4 KiB pages, which is the overwhelming majority of field
# images. Builds that diverge (ARM64, Server 2022) still parse enough of the
# header for us to compute ``total_pages`` and fall through to raw mode when
# the page-run tables turn out to be unrecoverable.
_OFF_SIGNATURE = 0x000
_OFF_VERSION = 0x004
_OFF_CHECKSUM = 0x008
_OFF_LENGTH_SELF = 0x00C
_OFF_PAGE_SELF = 0x010
_OFF_PAGE_SIZE = 0x018
_OFF_SYSTEM_TIME = 0x01C
# Fields between SystemTime and FirstTablePage vary per build; we read the
# specific words we need by offset below.
_OFF_FREE_MAP_CHECK = 0x044
_OFF_WAKE_CHECK = 0x048
_OFF_TOTAL_PAGES = 0x04C
_OFF_FIRST_TABLE_PAGE = 0x058
_OFF_LAST_FILE_PAGE = 0x060

# -- PO_MEMORY_RANGE_TABLE layout --------------------------------------------
# struct {
#   uint32_t PageCount;
#   uint32_t _pad;
#   uint64_t NextTable;    // page index of the next table, 0 terminates
#   MemoryRange Ranges[PageCount];
# };
# struct MemoryRange { uint64_t StartPage; uint64_t EndPage; };
_TABLE_HEADER_FMT = "<IIQ"
_TABLE_HEADER_SIZE = struct.calcsize(_TABLE_HEADER_FMT)
_RANGE_FMT = "<QQ"
_RANGE_SIZE = struct.calcsize(_RANGE_FMT)

# How many decompressed page-runs to keep in memory. 256 runs at 4 KiB each
# caps the cache at ~1 MiB per run if a single page.
_LRU_SIZE = 256

# Safety cap so a corrupted hiberfil cannot coerce us into allocating a
# billion-entry table chain.
_MAX_TABLES = 4096
_MAX_RANGES_PER_TABLE = 65536


class HibernationLayer(DataLayer):
    """Windows hibernation file (``hiberfil.sys``) layer.

    On construction the header is validated and the page-run table chain
    is *best-effort* walked. If any table is malformed, or if the Xpress
    decoder refuses to decode a run, the layer records
    ``compression_status = "undecoded"`` and serves the file's raw bytes
    via ``read()``. Scans and ``is_valid()`` still work in that mode.
    """

    #: Either ``"decoded"`` (page map populated) or ``"undecoded"``
    #: (raw pass-through fallback). Consumers can branch on this attribute.
    compression_status: str

    def __init__(self, path: Path, name: str = "") -> None:
        self._path = path
        self._name = name or "hibernation"
        self._size = path.stat().st_size
        self._file = open(path, "rb")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

        # Header fields. Defaults are conservative fallbacks.
        self._page_size = 0x1000
        self._total_pages = 0
        self._first_table_page = 0
        self._last_file_page = 0

        # Map of physical page number -> (file_offset, compressed_size).
        # Populated only when full parse succeeds.
        self._page_map: dict[int, tuple[int, int]] = {}

        # LRU cache of decompressed page runs keyed by the run's starting PFN.
        self._cache: OrderedDict[int, bytes] = OrderedDict()

        self.compression_status = "undecoded"

        self._validate_magic()
        self._parse_header()
        # Best-effort table walk. Any failure drops us to fallback mode.
        try:
            self._parse_tables()
            if self._page_map:
                self.compression_status = "decoded"
        except Exception:
            # Deliberately broad: corrupted hiberfils are common in the wild
            # and we would rather expose the raw bytes than refuse to load.
            self._page_map.clear()
            self.compression_status = "undecoded"

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def _validate_magic(self) -> None:
        if self._size < 4:
            raise FormatError("Hibernation file too small")
        magic = bytes(self._mmap[:4])
        if magic not in _VALID_MAGICS:
            raise FormatError(f"Not a valid hibernation file (magic: {magic!r})")

    def _u32(self, offset: int) -> int:
        return int(struct.unpack_from("<I", self._mmap, offset)[0])

    def _u64(self, offset: int) -> int:
        return int(struct.unpack_from("<Q", self._mmap, offset)[0])

    def _parse_header(self) -> None:
        # Only read fields we actually use. All others in PO_MEMORY_IMAGE
        # (checksum, self-length, perf info, NoHiberPtes, ResumeContext) are
        # deliberately skipped — they aren't required to address pages.
        if self._size < _OFF_LAST_FILE_PAGE + 8:
            # File is too short to contain the header fields we rely on.
            # Keep defaults; fallback mode will cover it.
            return
        ps = self._u32(_OFF_PAGE_SIZE)
        # Only honor standard page sizes; otherwise keep the 4 KiB default
        # rather than trusting a possibly-garbled value.
        if ps in (0x1000, 0x2000, 0x4000):
            self._page_size = ps
        self._total_pages = self._u32(_OFF_TOTAL_PAGES)
        self._first_table_page = self._u64(_OFF_FIRST_TABLE_PAGE)
        self._last_file_page = self._u64(_OFF_LAST_FILE_PAGE)

    # ------------------------------------------------------------------
    # Page-run table walk
    # ------------------------------------------------------------------

    def _parse_tables(self) -> None:
        if self._first_table_page == 0 or self._total_pages == 0:
            return

        file_pages = self._size // self._page_size
        next_page = self._first_table_page
        seen: set[int] = set()
        tables = 0

        # Successive compressed blocks sit sequentially starting after the
        # range-table page. We track the running file offset so each run
        # records where its compressed bytes live.
        cursor = (self._first_table_page + 1) * self._page_size

        while next_page != 0 and tables < _MAX_TABLES:
            if next_page in seen:
                # Cycle — treat as end.
                break
            seen.add(next_page)
            tables += 1

            table_off = next_page * self._page_size
            if table_off + _TABLE_HEADER_SIZE > self._size:
                break

            count, _pad, nxt = struct.unpack_from(
                _TABLE_HEADER_FMT, self._mmap, table_off
            )
            if count == 0 or count > _MAX_RANGES_PER_TABLE:
                break

            ranges_off = table_off + _TABLE_HEADER_SIZE
            if ranges_off + count * _RANGE_SIZE > self._size:
                break

            for i in range(count):
                start_page, end_page = struct.unpack_from(
                    _RANGE_FMT, self._mmap, ranges_off + i * _RANGE_SIZE
                )
                if end_page < start_page:
                    continue
                run_pages = end_page - start_page + 1
                # Compressed size is unknown from the header alone; we assume
                # the block is aligned to the next page boundary. Concretely
                # we record (cursor, run_pages * page_size) and let the
                # Xpress decoder size-check on decode.
                compressed_span = run_pages * self._page_size
                if cursor + 1 > self._size:
                    break
                for j in range(run_pages):
                    pfn = start_page + j
                    file_offset = cursor + j * self._page_size
                    if pfn >= file_pages:
                        continue
                    self._page_map[pfn] = (file_offset, self._page_size)
                cursor += compressed_span

            next_page = int(nxt)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_get(self, pfn: int) -> bytes | None:
        entry = self._cache.get(pfn)
        if entry is not None:
            self._cache.move_to_end(pfn)
        return entry

    def _cache_put(self, pfn: int, data: bytes) -> None:
        self._cache[pfn] = data
        self._cache.move_to_end(pfn)
        while len(self._cache) > _LRU_SIZE:
            self._cache.popitem(last=False)

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        if length <= 0:
            return b""
        if offset < 0:
            return b"\x00" * length if pad else b""

        # Fallback path: serve raw file bytes.
        if self.compression_status != "decoded":
            end = min(offset + length, self._size)
            if offset >= self._size:
                return b"\x00" * length if pad else b""
            data = bytes(self._mmap[offset:end])
            if pad and len(data) < length:
                data += b"\x00" * (length - len(data))
            return data

        # Decoded path: walk the page map.
        try:
            from deepview.storage.encodings.xpress import decompress_xpress
        except Exception:
            # Import failure -> degrade to raw mode for this call.
            self.compression_status = "undecoded"
            return self.read(offset, length, pad=pad)

        result = bytearray()
        remaining = length
        cur = offset
        page_size = self._page_size
        while remaining > 0:
            pfn = cur // page_size
            intra = cur % page_size
            page = self._cache_get(pfn)
            if page is None:
                mapping = self._page_map.get(pfn)
                if mapping is None:
                    if pad:
                        chunk_len = min(remaining, page_size - intra)
                        result.extend(b"\x00" * chunk_len)
                        remaining -= chunk_len
                        cur += chunk_len
                        continue
                    break
                file_off, comp_size = mapping
                end = min(file_off + comp_size, self._size)
                comp = bytes(self._mmap[file_off:end])
                try:
                    page = decompress_xpress(comp, page_size)
                except NotImplementedError:
                    # Permanent fallback: reset the layer and retry raw.
                    self.compression_status = "undecoded"
                    self._page_map.clear()
                    self._cache.clear()
                    return self.read(offset, length, pad=pad)
                except Exception:
                    if pad:
                        chunk_len = min(remaining, page_size - intra)
                        result.extend(b"\x00" * chunk_len)
                        remaining -= chunk_len
                        cur += chunk_len
                        continue
                    break
                if len(page) < page_size:
                    page = page + b"\x00" * (page_size - len(page))
                self._cache_put(pfn, page)
            take = min(remaining, page_size - intra)
            result.extend(page[intra:intra + take])
            remaining -= take
            cur += take
        if pad and len(result) < length:
            result.extend(b"\x00" * (length - len(result)))
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("Hibernation layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length <= 0:
            return False
        if self.compression_status == "decoded":
            end_pfn = (offset + length - 1) // self._page_size
            start_pfn = offset // self._page_size
            return all(p in self._page_map for p in range(start_pfn, end_pfn + 1))
        return offset + length <= self._size

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        if self.compression_status == "decoded" and self._total_pages > 0:
            return self._total_pages * self._page_size - 1
        return max(self._size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        extra_os = "windows"
        return LayerMetadata(
            name=self._name,
            os=extra_os,
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
        offset = 0
        while offset < total:
            data = self.read(offset, chunk_size, pad=False)
            if not data:
                break
            for result in scanner.scan(data, offset=offset):
                yield result
            offset += len(data)
            if progress_callback and total > 0:
                progress_callback(min(offset / total, 1.0))

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

    def __enter__(self) -> HibernationLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
