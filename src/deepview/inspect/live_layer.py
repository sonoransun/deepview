"""DataLayer adapter over ``/proc/[pid]/mem``.

Wraps a live process's address space so the existing YARA scanner
and string carver can operate on it without modification. Regions
come from ``/proc/[pid]/maps``; reads outside any mapped region
return zero-padded data when *pad* is true and raise otherwise.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterator

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


@dataclass
class MapRegion:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    pathname: str


class LiveProcessLayer(DataLayer):
    """Read-only ``DataLayer`` over a live process's virtual memory."""

    def __init__(self, pid: int) -> None:
        self._pid = pid
        self._regions: list[MapRegion] = []
        self._fd: int | None = None
        self._load_maps()

    @property
    def pid(self) -> int:
        return self._pid

    def _load_maps(self) -> None:
        path = f"/proc/{self._pid}/maps"
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split(maxsplit=5)
                    if len(parts) < 5:
                        continue
                    addrs = parts[0].split("-")
                    if len(addrs) != 2:
                        continue
                    try:
                        start = int(addrs[0], 16)
                        end = int(addrs[1], 16)
                    except ValueError:
                        continue
                    perms = parts[1]
                    try:
                        offset = int(parts[2], 16)
                    except ValueError:
                        offset = 0
                    dev = parts[3]
                    try:
                        inode = int(parts[4])
                    except ValueError:
                        inode = 0
                    pathname = parts[5].strip() if len(parts) > 5 else ""
                    self._regions.append(
                        MapRegion(start, end, perms, offset, dev, inode, pathname)
                    )
        except OSError:
            # Pid missing or permission denied; leave region list empty.
            return

    def _open(self) -> int:
        if self._fd is None:
            self._fd = os.open(f"/proc/{self._pid}/mem", os.O_RDONLY)
        return self._fd

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        region = self._find_region(offset)
        if region is None:
            if pad:
                return b"\x00" * length
            from deepview.core.exceptions import LayerError

            raise LayerError(f"address 0x{offset:x} not mapped in pid {self._pid}")
        try:
            fd = self._open()
            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, length)
            if len(data) < length and pad:
                data += b"\x00" * (length - len(data))
            return data
        except OSError as e:
            if pad:
                return b"\x00" * length
            from deepview.core.exceptions import LayerError

            raise LayerError(f"read failed at 0x{offset:x}: {e}") from e

    def write(self, offset: int, data: bytes) -> None:
        from deepview.core.exceptions import LayerError

        raise LayerError("LiveProcessLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        region = self._find_region(offset)
        if region is None:
            return False
        return offset + length <= region.end

    def scan(
        self,
        scanner,  # PatternScanner
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        for region in self._regions:
            size = region.end - region.start
            if size <= 0 or "r" not in region.perms:
                continue
            try:
                data = self.read(region.start, size, pad=True)
            except Exception:  # noqa: BLE001
                continue
            for result in scanner.scan(data):
                # Translate the scanner's region-relative offset back to
                # the absolute virtual address so callers can correlate.
                yield ScanResult(
                    offset=region.start + result.offset,
                    length=result.length,
                    rule_name=result.rule_name,
                    data=result.data,
                    metadata={**result.metadata, "pathname": region.pathname},
                )
            if progress_callback is not None:
                progress_callback(region.start, region.end)

    @property
    def minimum_address(self) -> int:
        return self._regions[0].start if self._regions else 0

    @property
    def maximum_address(self) -> int:
        return self._regions[-1].end if self._regions else 0

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=f"pid-{self._pid}",
            os="linux",
            arch="x86_64",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def regions(self) -> list[MapRegion]:
        return list(self._regions)

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass
