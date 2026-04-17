"""Hyper-V ``.vmrs`` / ``.bin`` savedstate memory layer.

Hyper-V's runtime-savedstate pair consists of a ``.vmrs`` metadata file and
a ``.bin`` raw RAM file. The ``.vmrs`` includes a Guest Physical Address
Descriptor List (GPADL) describing how guest physical regions map into the
``.bin`` backing store. The full format is Microsoft-internal; we parse a
best-effort header (magic + region count) and, failing that, fall back to
treating the ``.bin`` as a flat image.
"""
from __future__ import annotations

import mmap
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


# Observed magic strings at the start of ``.vmrs`` files. Hyper-V has
# revised this a few times; these are accepted as recognition hints.
_VMRS_MAGICS: tuple[bytes, ...] = (b"VMRS", b"\xd0\x0d\xf0\x0d")


@dataclass(frozen=True)
class GPADLRegion:
    """One entry of the GPADL table."""

    guest_address: int
    size: int
    file_offset: int


class HyperVVMRSLayer(DataLayer):
    """VMRS metadata + BIN-backed memory layer."""

    def __init__(
        self,
        vmrs_path: Path,
        *,
        bin_path: Path | None = None,
        name: str = "",
    ) -> None:
        self._vmrs_path = vmrs_path
        if bin_path is None:
            bin_path = vmrs_path.with_suffix(".bin")
        self._bin_path = bin_path
        self._name = name or "hyperv_vmrs"

        # The .bin is the RAM backing store.
        if not bin_path.exists():
            raise FileNotFoundError(
                f"Hyper-V .bin savedstate file not found: {bin_path}"
            )
        self._bin_size = bin_path.stat().st_size
        self._bin_file: BinaryIO | None = open(bin_path, "rb")
        self._bin_mmap: mmap.mmap | None = None
        if self._bin_size > 0:
            self._bin_mmap = mmap.mmap(
                self._bin_file.fileno(), 0, access=mmap.ACCESS_READ
            )

        self._regions: list[GPADLRegion] = []
        self._parsed_gpadl = False
        if vmrs_path.exists():
            try:
                self._regions = self._try_parse_vmrs(vmrs_path, self._bin_size)
                self._parsed_gpadl = bool(self._regions)
            except Exception:
                self._regions = []
                self._parsed_gpadl = False

    # ------------------------------------------------------------------
    # VMRS header parsing (heuristic)
    # ------------------------------------------------------------------

    @staticmethod
    def _try_parse_vmrs(path: Path, bin_size: int) -> list[GPADLRegion]:
        """Very-best-effort GPADL extraction.

        Returns the region list if recognisable; otherwise an empty list
        (the layer will fall back to flat passthrough of the .bin).
        """
        try:
            raw = path.read_bytes()
        except OSError:
            return []
        if len(raw) < 16:
            return []
        matched = False
        for magic in _VMRS_MAGICS:
            if raw.startswith(magic):
                matched = True
                break
        if not matched:
            return []
        # The region count lives somewhere in the header; without the spec
        # we cannot reliably synthesize a GPADL table. Return [] so callers
        # exercise flat passthrough — explicit is better than fabricated.
        return []

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if self._parsed_gpadl and self._regions:
            return self._read_gpadl(offset, length, pad=pad)
        return self._read_flat(offset, length, pad=pad)

    def _read_flat(self, offset: int, length: int, *, pad: bool) -> bytes:
        if offset < 0 or offset >= self._bin_size:
            return b"\x00" * length if pad else b""
        end = min(offset + length, self._bin_size)
        assert self._bin_mmap is not None
        data = bytes(self._bin_mmap[offset:end])
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def _read_gpadl(self, offset: int, length: int, *, pad: bool) -> bytes:
        assert self._bin_mmap is not None
        out = bytearray()
        current = offset
        remaining = length
        while remaining > 0:
            region = self._find_region(current)
            if region is None:
                if not pad:
                    break
                next_start = self._next_region_start(current)
                gap = (
                    min(next_start - current, remaining)
                    if next_start is not None
                    else remaining
                )
                out.extend(b"\x00" * gap)
                current += gap
                remaining -= gap
                continue
            local = current - region.guest_address
            available = region.size - local
            take = min(remaining, available)
            file_start = region.file_offset + local
            file_end = min(file_start + take, self._bin_size)
            take = max(file_end - file_start, 0)
            if take == 0:
                if pad:
                    out.extend(b"\x00" * remaining)
                break
            out.extend(bytes(self._bin_mmap[file_start:file_end]))
            current += take
            remaining -= take
        return bytes(out)

    def _find_region(self, offset: int) -> GPADLRegion | None:
        for r in self._regions:
            if r.guest_address <= offset < r.guest_address + r.size:
                return r
        return None

    def _next_region_start(self, offset: int) -> int | None:
        nxt: int | None = None
        for r in self._regions:
            if r.guest_address > offset and (
                nxt is None or r.guest_address < nxt
            ):
                nxt = r.guest_address
        return nxt

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("HyperVVMRSLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        if self._parsed_gpadl and self._regions:
            end = offset + length
            cur = offset
            while cur < end:
                region = self._find_region(cur)
                if region is None:
                    return False
                cur = min(end, region.guest_address + region.size)
            return True
        return offset + length <= self._bin_size

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        if self._bin_mmap is None or self._bin_size == 0:
            return
        chunk_size = 4 * 1024 * 1024
        overlap = 4096
        offset = 0
        while offset < self._bin_size:
            end = min(offset + chunk_size, self._bin_size)
            chunk = bytes(self._bin_mmap[offset:end])
            for result in scanner.scan(chunk, offset=offset):
                yield result
            if progress_callback is not None:
                progress_callback(end / self._bin_size)
            offset = end - overlap if end < self._bin_size else end

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def minimum_address(self) -> int:
        if self._parsed_gpadl and self._regions:
            return min(r.guest_address for r in self._regions)
        return 0

    @property
    def maximum_address(self) -> int:
        if self._parsed_gpadl and self._regions:
            return max(r.guest_address + r.size - 1 for r in self._regions)
        return max(self._bin_size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        suffix = " (gpadl)" if self._parsed_gpadl else " (flat)"
        return LayerMetadata(
            name=f"{self._name}:{self._vmrs_path.name}+{self._bin_path.name}"
            + suffix,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def regions(self) -> list[GPADLRegion]:
        return list(self._regions)

    @property
    def parsed_gpadl(self) -> bool:
        return self._parsed_gpadl

    @property
    def bin_path(self) -> Path:
        return self._bin_path

    @property
    def vmrs_path(self) -> Path:
        return self._vmrs_path

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._bin_mmap is not None:
            try:
                self._bin_mmap.close()
            except ValueError:
                pass
            self._bin_mmap = None
        if self._bin_file is not None:
            try:
                self._bin_file.close()
            except Exception:
                pass
            self._bin_file = None

    def __enter__(self) -> HyperVVMRSLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

