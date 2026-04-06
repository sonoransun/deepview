"""ELF core dump format parser."""
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

# ELF constants
ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
PT_NOTE = 4
ELFCLASS64 = 2
ELFDATA2LSB = 1  # Little endian


@dataclass
class ELFSegment:
    """An ELF PT_LOAD segment."""

    vaddr: int
    paddr: int
    file_offset: int
    file_size: int
    mem_size: int
    flags: int


class ELFCoreLayer(DataLayer):
    """ELF core dump memory layer. Maps PT_LOAD segments to physical addresses."""

    def __init__(self, path: Path, name: str = "", use_physical: bool = True):
        self._path = path
        self._name = name or path.name
        self._use_physical = use_physical
        self._segments: list[ELFSegment] = []
        self._file = open(path, "rb")
        self._parse_elf()

    _MAX_PHNUM = 65536  # Reasonable upper bound for program headers.

    def _parse_elf(self) -> None:
        """Parse ELF header and program headers."""
        self._file.seek(0, 2)
        file_size = self._file.tell()
        self._file.seek(0)

        ident = self._file.read(16)
        if len(ident) < 16 or ident[:4] != ELF_MAGIC:
            raise FormatError("Not a valid ELF file")

        elfclass = ident[4]
        if elfclass != ELFCLASS64:
            raise FormatError("Only 64-bit ELF cores are supported")

        # ELF64 header (after ident)
        hdr = self._file.read(48)  # remaining header fields
        if len(hdr) < 48:
            raise FormatError("Truncated ELF header")

        e_type, e_machine, e_version = struct.unpack_from("<HHI", hdr, 0)
        e_phoff = struct.unpack_from("<Q", hdr, 16)[0]
        e_phentsize = struct.unpack_from("<H", hdr, 34)[0]
        e_phnum = struct.unpack_from("<H", hdr, 36)[0]

        if e_phnum > self._MAX_PHNUM:
            raise FormatError(f"Too many program headers: {e_phnum} (max {self._MAX_PHNUM})")

        if e_phoff + e_phnum * e_phentsize > file_size:
            raise FormatError("Program header table extends past end of file")

        # Parse program headers
        self._file.seek(e_phoff)
        for _ in range(e_phnum):
            phdr_data = self._file.read(e_phentsize)
            if len(phdr_data) < 56:
                break
            p_type = struct.unpack_from("<I", phdr_data, 0)[0]
            if p_type == PT_LOAD:
                p_flags = struct.unpack_from("<I", phdr_data, 4)[0]
                p_offset = struct.unpack_from("<Q", phdr_data, 8)[0]
                p_vaddr = struct.unpack_from("<Q", phdr_data, 16)[0]
                p_paddr = struct.unpack_from("<Q", phdr_data, 24)[0]
                p_filesz = struct.unpack_from("<Q", phdr_data, 32)[0]
                p_memsz = struct.unpack_from("<Q", phdr_data, 40)[0]

                # Validate segment doesn't extend past file.
                if p_offset + p_filesz > file_size:
                    raise FormatError(
                        f"PT_LOAD segment extends past file "
                        f"(offset=0x{p_offset:x}, size=0x{p_filesz:x}, file_size={file_size})"
                    )

                self._segments.append(ELFSegment(
                    vaddr=p_vaddr,
                    paddr=p_paddr,
                    file_offset=p_offset,
                    file_size=p_filesz,
                    mem_size=p_memsz,
                    flags=p_flags,
                ))

    def _addr(self, seg: ELFSegment) -> int:
        """Get the address to use for this segment (physical or virtual)."""
        return seg.paddr if self._use_physical else seg.vaddr

    def _find_segment(self, offset: int) -> ELFSegment | None:
        for seg in self._segments:
            addr = self._addr(seg)
            if addr <= offset < addr + seg.file_size:
                return seg
        return None

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        result = bytearray()
        remaining = length
        current = offset

        while remaining > 0:
            seg = self._find_segment(current)
            if seg is None:
                if pad:
                    result.extend(b"\x00" * remaining)
                break

            addr = self._addr(seg)
            seg_offset = current - addr
            available = seg.file_size - seg_offset
            to_read = min(remaining, available)

            self._file.seek(seg.file_offset + seg_offset)
            data = self._file.read(to_read)
            result.extend(data)

            remaining -= len(data)
            current += len(data)

        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("ELF core layers are read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self._find_segment(offset) is not None

    @property
    def minimum_address(self) -> int:
        if not self._segments:
            return 0
        return min(self._addr(s) for s in self._segments)

    @property
    def maximum_address(self) -> int:
        if not self._segments:
            return 0
        return max(self._addr(s) + s.file_size for s in self._segments)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    def scan(self, scanner: PatternScanner, progress_callback: Callable | None = None) -> Iterator[ScanResult]:
        total = sum(s.file_size for s in self._segments)
        scanned = 0
        for seg in self._segments:
            addr = self._addr(seg)
            self._file.seek(seg.file_offset)
            data = self._file.read(seg.file_size)
            for result in scanner.scan(data, offset=addr):
                yield result
            scanned += seg.file_size
            if progress_callback:
                progress_callback(scanned / total if total > 0 else 1.0)

    def close(self) -> None:
        if self._file:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
