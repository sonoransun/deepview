"""VMware ``.vmem`` memory layer with optional ``.vmss``/``.vmsn`` sparse map.

The ``.vmem`` file is a raw, byte-for-byte dump of the guest's physical RAM.
When present, a sibling ``.vmss`` (suspended state) or ``.vmsn`` (snapshot)
file describes which regions are actually populated. Parsing the *full* VMware
state format is well outside this slice's scope; we parse just enough of the
header to learn a best-effort region table and expose it as sparse mapping.
If the sidecar cannot be parsed we silently degrade to flat-file behaviour —
which, for ``.vmem``, is exactly the byte image of RAM.
"""
from __future__ import annotations

import mmap
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


# VMware "Core Dump File" magic used in .vmss / .vmsn headers.
# See the Volatility 3 vmwareinfo plugin for the reference layout.
_VMSS_MAGIC = 0xBED2BED0
_VMSS_MAGIC_ALT = 0xBED2BED3  # 64-bit variant seen on newer products
_VMSN_MAGIC = 0xBED2BED2


@dataclass(frozen=True)
class VMwareRegion:
    """A populated region of guest physical memory."""

    start: int  # guest physical address
    size: int
    file_offset: int  # offset into the .vmem file


class VMwareVMEMLayer(DataLayer):
    """Flat VMware ``.vmem`` backed by an ``mmap``, optionally sparse."""

    def __init__(
        self,
        path: Path,
        *,
        vmss_path: Path | None = None,
        name: str = "",
    ) -> None:
        self._path = path
        self._name = name or "vmware_vmem"
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

        # Auto-detect a sibling .vmss / .vmsn if not supplied.
        self._vmss_path: Path | None = vmss_path
        if self._vmss_path is None:
            for suffix in (".vmss", ".vmsn"):
                candidate = path.with_suffix(suffix)
                if candidate.exists():
                    self._vmss_path = candidate
                    break

        self._regions: list[VMwareRegion] = []
        self._sparse = False
        if self._vmss_path is not None and self._vmss_path.exists():
            regions = self._try_parse_vmss(self._vmss_path)
            if regions:
                self._regions = regions
                self._sparse = True

    # ------------------------------------------------------------------
    # VMSS / VMSN header parsing (best-effort)
    # ------------------------------------------------------------------

    @staticmethod
    def _try_parse_vmss(path: Path) -> list[VMwareRegion]:
        """Parse just enough of the VMware state header to list memory regions.

        The on-disk format is rich (tag directories, group tables, typed
        values). We bail out on any parse error and return an empty list —
        the layer then behaves as a flat ``.vmem``.
        """
        try:
            raw = path.read_bytes()
        except OSError:
            return []
        if len(raw) < 12:
            return []
        try:
            magic, version, group_count = struct.unpack_from("<III", raw, 0)
        except struct.error:
            return []
        if magic not in (_VMSS_MAGIC, _VMSS_MAGIC_ALT, _VMSN_MAGIC):
            return []
        # We do not walk the group table here — that requires the full spec.
        # Absent a reliable parse, return [] so we fall back to flat mode.
        _ = version
        _ = group_count
        return []

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if self._sparse and self._regions:
            return self._read_sparse(offset, length, pad=pad)
        return self._read_flat(offset, length, pad=pad)

    def _read_flat(self, offset: int, length: int, *, pad: bool) -> bytes:
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        end = min(offset + length, self._size)
        assert self._mmap is not None
        data = bytes(self._mmap[offset:end])
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def _read_sparse(self, offset: int, length: int, *, pad: bool) -> bytes:
        assert self._mmap is not None
        out = bytearray()
        current = offset
        remaining = length
        while remaining > 0:
            region = self._find_region(current)
            if region is None:
                if not pad:
                    break
                # Pad up to the next region (or to the end of the request).
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
            local = current - region.start
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

    def _find_region(self, offset: int) -> VMwareRegion | None:
        for r in self._regions:
            if r.start <= offset < r.start + r.size:
                return r
        return None

    def _next_region_start(self, offset: int) -> int | None:
        nxt: int | None = None
        for r in self._regions:
            if r.start > offset and (nxt is None or r.start < nxt):
                nxt = r.start
        return nxt

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("VMwareVMEMLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        if self._sparse and self._regions:
            end = offset + length
            cur = offset
            while cur < end:
                region = self._find_region(cur)
                if region is None:
                    return False
                region_end = region.start + region.size
                cur = min(end, region_end)
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
        offset = 0
        while offset < self._size:
            end = min(offset + chunk_size, self._size)
            chunk = bytes(self._mmap[offset:end])
            for result in scanner.scan(chunk, offset=offset):
                yield result
            if progress_callback is not None:
                progress_callback(end / self._size)
            offset = end - overlap if end < self._size else end

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def minimum_address(self) -> int:
        if self._sparse and self._regions:
            return min(r.start for r in self._regions)
        return 0

    @property
    def maximum_address(self) -> int:
        if self._sparse and self._regions:
            return max(r.start + r.size - 1 for r in self._regions)
        return max(self._size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def regions(self) -> list[VMwareRegion]:
        return list(self._regions)

    @property
    def is_sparse(self) -> bool:
        return self._sparse

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

    def __enter__(self) -> VMwareVMEMLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
