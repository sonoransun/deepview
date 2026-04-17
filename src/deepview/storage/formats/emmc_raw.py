"""Raw eMMC image DataLayer.

An eMMC image is a flat byte image of the user-data area (and sometimes the
boot partitions concatenated in front). We expose it as a flat ``mmap``-backed
layer and additionally probe for MBR / GPT signatures at the standard offsets
so callers can see where boot1 / boot2 / user / RPMB start without having to
re-parse headers themselves. The boot-partition layout is a vendor hint — we
do not overlay partition logic here.
"""
from __future__ import annotations

import mmap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


# Standard offsets (in blocks of 512 B) for eMMC hardware partitions. The
# image's own offsets here are synthesized heuristically — real-world dumps
# are commonly either (a) just the user area, or (b) boot1 + boot2 + user
# concatenated in that order. We surface the heuristic values so downstream
# tooling can decide whether to trust them.
_MBR_SIGNATURE_OFFSET = 0x1FE
_MBR_SIGNATURE = b"\x55\xAA"
_GPT_HEADER_OFFSET = 0x200  # LBA 1 for 512 B sectors
_GPT_SIGNATURE = b"EFI PART"


class EMMCRawLayer(DataLayer):
    """Flat eMMC dump with best-effort boot-region offsets."""

    def __init__(
        self,
        path: Path,
        name: str = "",
        block_size: int = 512,
    ) -> None:
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        self._path = path
        self._name = name or "emmc_raw"
        self._block_size = block_size
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

        # Heuristic partition probe. Populated as instance attributes — no
        # LayerMetadata.extra exists in the core types.
        self.boot1_offset: int | None = None
        self.boot2_offset: int | None = None
        self.rpmb_offset: int | None = None
        self.has_mbr: bool = False
        self.has_gpt: bool = False
        self._probe_partitions()

    # ------------------------------------------------------------------
    # Partition probing
    # ------------------------------------------------------------------

    def _probe_partitions(self) -> None:
        if self._mmap is None or self._size < 0x200:
            return
        try:
            sig = bytes(
                self._mmap[_MBR_SIGNATURE_OFFSET : _MBR_SIGNATURE_OFFSET + 2]
            )
            self.has_mbr = sig == _MBR_SIGNATURE
        except Exception:
            self.has_mbr = False
        if self._size >= _GPT_HEADER_OFFSET + 8:
            try:
                gpt = bytes(
                    self._mmap[_GPT_HEADER_OFFSET : _GPT_HEADER_OFFSET + 8]
                )
                self.has_gpt = gpt == _GPT_SIGNATURE
            except Exception:
                self.has_gpt = False
        # Typical hints for concatenated boot1+boot2+user dumps: 4 MiB each
        # boot partition, RPMB sitting after. We only expose these when the
        # file is at least large enough to contain them.
        guess = 4 * 1024 * 1024
        if self._size >= 3 * guess:
            self.boot1_offset = 0
            self.boot2_offset = guess
            self.rpmb_offset = 2 * guess

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        end = min(offset + length, self._size)
        if self._mmap is None:
            return b"\x00" * length if pad else b""
        data = bytes(self._mmap[offset:end])
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("EMMCRawLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return (
            offset >= 0 and length >= 0 and offset + length <= self._size
        )

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
        return 0

    @property
    def maximum_address(self) -> int:
        return max(self._size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    @property
    def block_size(self) -> int:
        return self._block_size

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

    def __enter__(self) -> EMMCRawLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
