"""Swap-space DataLayers: Linux v1_01 + Windows pagefile.sys.

Linux swap format (kernel, mm/swapfile.c)
-----------------------------------------
A Linux swap partition is a sequence of 4 KiB pages. Page 0 is the
``union swap_header`` and contains:

* offsets 0..1024  — optional boot-sector payload (ignored here).
* ``info.version`` (u32 at offset 1024)  — must be ``1``.
* ``info.last_page`` (u32 at 1028)       — index of the last usable page.
* ``info.nr_badpages`` (u32 at 1032)     — count of bad-page entries (0..N).
* ``info.uuid``[16] + ``info.volume_name``[16] — identifiers.
* ``info.padding[117]`` + ``info.badpages[1..]`` — u32 bad-page indices.
* the 10-byte ASCII magic ``SWAPSPACE2`` sits at offset 4086 (page 0's last
  10 bytes minus the trailing u32 checksum slot).

This layer flattens pages 1..last_page into a contiguous byte-stream, with
pages in the bad-page list returning zeros.

Windows pagefile.sys
--------------------
A pagefile is an opaque flat collection of 4 KiB pages with no embedded
index — the mapping from virtual swap frames to file offsets lives in the
kernel's ``MMPFN`` database. Without live kernel access we treat it as a
flat passthrough with an optional sidecar JSON describing valid page runs
(``[{"offset": 0, "length": 16384}, ...]``). Reads outside declared runs
return zeros when ``pad=True`` and raise otherwise.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner

__all__ = ["LinuxSwapLayer", "WindowsSwapLayer"]


LINUX_SWAP_PAGE_SIZE = 4096
LINUX_SWAP_MAGIC = b"SWAPSPACE2"
LINUX_SWAP_MAGIC_OFFSET = 4086


class LinuxSwapLayer(DataLayer):
    """Linux swap v1_01 area exposed as a flat DataLayer."""

    def __init__(self, backing: DataLayer, name: str = "") -> None:
        self._backing = backing
        self._name = name or "linux_swap"
        header = backing.read(0, LINUX_SWAP_PAGE_SIZE, pad=True)
        magic = header[LINUX_SWAP_MAGIC_OFFSET:LINUX_SWAP_MAGIC_OFFSET + len(LINUX_SWAP_MAGIC)]
        if magic != LINUX_SWAP_MAGIC:
            raise ValueError(
                f"LinuxSwapLayer: missing SWAPSPACE2 magic at offset "
                f"{LINUX_SWAP_MAGIC_OFFSET} (got {magic!r})"
            )
        version = int.from_bytes(header[1024:1028], "little")
        if version != 1:
            raise ValueError(f"LinuxSwapLayer: unsupported version {version}")
        self._last_page = int.from_bytes(header[1028:1032], "little")
        nr_bad = int.from_bytes(header[1032:1036], "little")
        # Layout (from Linux ``union swap_header.info``):
        #   u32 version        @ 1024
        #   u32 last_page      @ 1028
        #   u32 nr_badpages    @ 1032
        #   u8  sws_uuid[16]   @ 1036
        #   u8  sws_volume[16] @ 1052
        #   u32 padding[117]   @ 1068
        #   u32 badpages[]     @ 1536
        bad_offset = 1068 + (117 * 4)
        bad_pages: set[int] = set()
        for i in range(min(nr_bad, (LINUX_SWAP_PAGE_SIZE - bad_offset) // 4)):
            idx = int.from_bytes(header[bad_offset + i * 4:bad_offset + (i + 1) * 4], "little")
            bad_pages.add(idx)
        self._bad_pages = bad_pages

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        result = bytearray()
        remaining = length
        cur = offset
        end_addr = self.maximum_address
        while remaining > 0:
            if cur < 0 or cur > end_addr:
                if pad:
                    result.extend(b"\x00" * remaining)
                    return bytes(result)
                break
            # Page indices in the exposed address-space are 1..last_page;
            # offset 0 maps to backing page 1.
            exposed_page = cur // LINUX_SWAP_PAGE_SIZE
            page_offset = cur % LINUX_SWAP_PAGE_SIZE
            available = LINUX_SWAP_PAGE_SIZE - page_offset
            chunk = min(remaining, available)
            backing_page = exposed_page + 1
            if backing_page in self._bad_pages:
                result.extend(b"\x00" * chunk)
            else:
                page_data = self._backing.read(
                    backing_page * LINUX_SWAP_PAGE_SIZE + page_offset, chunk, pad=True
                )
                result.extend(page_data)
            cur += chunk
            remaining -= chunk
        if pad and len(result) < length:
            result.extend(b"\x00" * (length - len(result)))
        return bytes(result)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("LinuxSwapLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        return offset + length <= self.maximum_address + 1

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        yield from scanner.scan_layer(self, progress_callback=progress_callback)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def last_page(self) -> int:
        return self._last_page

    @property
    def bad_pages(self) -> frozenset[int]:
        return frozenset(self._bad_pages)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        # Flattened usable area: pages 1..last_page -> last_page pages total.
        return max(self._last_page * LINUX_SWAP_PAGE_SIZE - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            os="linux",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )


class WindowsSwapLayer(DataLayer):
    """Windows ``pagefile.sys`` as a flat DataLayer.

    Without a kernel-side index the pagefile is opaque; callers may supply
    a sidecar JSON file enumerating ``[{"offset": int, "length": int}]``
    runs that are known to be valid. Reads inside a declared run pass
    through; reads elsewhere return zeros when *pad* is set.
    """

    def __init__(
        self,
        backing: DataLayer,
        valid_runs: list[tuple[int, int]] | None = None,
        name: str = "",
    ) -> None:
        self._backing = backing
        self._name = name or "windows_pagefile"
        self._valid_runs: list[tuple[int, int]] = list(valid_runs or [])
        self._passthrough = not self._valid_runs

    @classmethod
    def from_sidecar(
        cls,
        backing: DataLayer,
        sidecar: Path,
        name: str = "",
    ) -> WindowsSwapLayer:
        raw = sidecar.read_text(encoding="utf-8")
        entries = json.loads(raw)
        runs = [(int(e["offset"]), int(e["length"])) for e in entries]
        return cls(backing, valid_runs=runs, name=name)

    def _in_valid_run(self, offset: int, length: int) -> bool:
        if self._passthrough:
            return True
        for start, rlen in self._valid_runs:
            if offset >= start and offset + length <= start + rlen:
                return True
        return False

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if self._passthrough:
            return self._backing.read(offset, length, pad=pad)
        if self._in_valid_run(offset, length):
            return self._backing.read(offset, length, pad=pad)
        if pad:
            return b"\x00" * length
        raise ValueError(
            f"WindowsSwapLayer: read [{offset}, {offset + length}) outside "
            "any declared valid run"
        )

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("WindowsSwapLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        if self._passthrough:
            return self._backing.is_valid(offset, length)
        return self._in_valid_run(offset, length)

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        yield from scanner.scan_layer(self, progress_callback=progress_callback)

    @property
    def minimum_address(self) -> int:
        return self._backing.minimum_address

    @property
    def maximum_address(self) -> int:
        return self._backing.maximum_address

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            os="windows",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )
