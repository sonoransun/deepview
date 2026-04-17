"""JTAG RAM dump DataLayer with optional JSON region sidecar.

OpenOCD / Segger-style multi-region JTAG dumps are frequently saved as a flat
binary plus a JSON sidecar describing how byte ranges in the file map to
virtual addresses in the target's address space. The sidecar schema is::

    [
        {"offset": 0x20000000, "size": 0x8000,  "name": "SRAM",
         "file_offset": 0},
        {"offset": 0x08000000, "size": 0x40000, "name": "Flash",
         "file_offset": 0x8000}
    ]

When the sidecar is absent the layer is a flat passthrough of the file.
"""
from __future__ import annotations

import json
import mmap
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


@dataclass(frozen=True)
class JTAGRegion:
    """Virtual-address -> file-offset mapping for one JTAG dump region."""

    name: str
    virtual_address: int
    size: int
    file_offset: int


class JTAGRAMLayer(DataLayer):
    """Multi-region JTAG dump; flat passthrough when no sidecar is present."""

    def __init__(
        self,
        path: Path,
        *,
        sidecar: Path | None = None,
        name: str = "",
    ) -> None:
        self._path = path
        self._name = name or "jtag_ram"
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

        if sidecar is None:
            candidate = path.with_suffix(".json")
            if candidate.exists():
                sidecar = candidate
        self._sidecar_path = sidecar

        self._regions: list[JTAGRegion] = []
        if sidecar is not None and sidecar.exists():
            self._regions = self._parse_sidecar(sidecar, self._size)
        self._multi_region = bool(self._regions)
        self._regions.sort(key=lambda r: r.virtual_address)

    # ------------------------------------------------------------------
    # Sidecar parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_sidecar(path: Path, file_size: int) -> list[JTAGRegion]:
        try:
            raw = path.read_text(encoding="utf-8")
            doc = json.loads(raw)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(doc, list):
            return []
        regions: list[JTAGRegion] = []
        for entry in doc:
            if not isinstance(entry, dict):
                continue
            va = entry.get("offset")
            size = entry.get("size")
            file_off = entry.get("file_offset", 0)
            name = entry.get("name", "")
            if not isinstance(va, int) or not isinstance(size, int):
                continue
            if not isinstance(file_off, int) or not isinstance(name, str):
                continue
            if va < 0 or size < 0 or file_off < 0:
                continue
            if file_off + size > file_size:
                # Clamp but don't drop — a short tail is common.
                size = max(file_size - file_off, 0)
                if size == 0:
                    continue
            regions.append(
                JTAGRegion(
                    name=name,
                    virtual_address=va,
                    size=size,
                    file_offset=file_off,
                )
            )
        return regions

    def _find_region(self, offset: int) -> JTAGRegion | None:
        for r in self._regions:
            if r.virtual_address <= offset < r.virtual_address + r.size:
                return r
        return None

    def _next_region_start(self, offset: int) -> int | None:
        nxt: int | None = None
        for r in self._regions:
            if r.virtual_address > offset and (
                nxt is None or r.virtual_address < nxt
            ):
                nxt = r.virtual_address
        return nxt

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if self._multi_region:
            return self._read_multi(offset, length, pad=pad)
        return self._read_flat(offset, length, pad=pad)

    def _read_flat(self, offset: int, length: int, *, pad: bool) -> bytes:
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        end = min(offset + length, self._size)
        if self._mmap is None:
            return b"\x00" * length if pad else b""
        data = bytes(self._mmap[offset:end])
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def _read_multi(self, offset: int, length: int, *, pad: bool) -> bytes:
        assert self._mmap is not None
        out = bytearray()
        current = offset
        remaining = length
        while remaining > 0:
            region = self._find_region(current)
            if region is None:
                if not pad:
                    break
                nxt = self._next_region_start(current)
                gap = (
                    min(nxt - current, remaining) if nxt is not None else remaining
                )
                out.extend(b"\x00" * gap)
                current += gap
                remaining -= gap
                continue
            local = current - region.virtual_address
            available = region.size - local
            take = min(remaining, available)
            file_start = region.file_offset + local
            file_end = file_start + take
            if file_end > self._size:
                file_end = self._size
                take = file_end - file_start
                if take <= 0:
                    if pad:
                        out.extend(b"\x00" * remaining)
                    break
            out.extend(bytes(self._mmap[file_start:file_end]))
            current += take
            remaining -= take
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("JTAGRAMLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        if self._multi_region:
            end = offset + length
            cur = offset
            while cur < end:
                region = self._find_region(cur)
                if region is None:
                    return False
                cur = min(end, region.virtual_address + region.size)
            return True
        return offset + length <= self._size

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        if self._mmap is None or self._size == 0:
            return
        chunk_size = 4 * 1024 * 1024
        overlap = 4096
        if not self._multi_region:
            offset = 0
            while offset < self._size:
                end = min(offset + chunk_size, self._size)
                chunk = bytes(self._mmap[offset:end])
                for result in scanner.scan(chunk, offset=offset):
                    yield result
                if progress_callback is not None:
                    progress_callback(end / self._size)
                offset = end - overlap if end < self._size else end
            return
        total = sum(r.size for r in self._regions)
        scanned = 0
        for region in self._regions:
            pos = 0
            while pos < region.size:
                read_size = min(chunk_size, region.size - pos)
                file_start = region.file_offset + pos
                file_end = file_start + read_size
                chunk = bytes(self._mmap[file_start:file_end])
                for result in scanner.scan(
                    chunk, offset=region.virtual_address + pos
                ):
                    yield result
                if pos + read_size >= region.size:
                    break
                pos += read_size - overlap
            scanned += region.size
            if progress_callback is not None and total > 0:
                progress_callback(scanned / total)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def minimum_address(self) -> int:
        if self._multi_region:
            return self._regions[0].virtual_address
        return 0

    @property
    def maximum_address(self) -> int:
        if self._multi_region:
            last = self._regions[-1]
            return last.virtual_address + last.size - 1
        return max(self._size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def regions(self) -> list[JTAGRegion]:
        return list(self._regions)

    @property
    def is_multi_region(self) -> bool:
        return self._multi_region

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

    def __enter__(self) -> JTAGRAMLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
