"""Raw SPI-NOR flash dump DataLayer with optional SFDP parsing.

SPI-NOR flash images are flat byte streams. If the image contains a Serial
Flash Discoverable Parameters (SFDP) block starting with the ASCII signature
``"SFDP"``, we parse enough of it to learn the declared total flash size.
Otherwise we just use the file size. SFDP may appear at offset 0 of some
images (when the dump is the descriptor region only) or at the address
pointed to by a vendor descriptor in a larger image — we only probe offset 0.
"""
from __future__ import annotations

import mmap
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


_SFDP_SIGNATURE = b"SFDP"


class SPIFlashLayer(DataLayer):
    """Flat SPI-NOR / SPI-flash dump with SFDP best-effort probe."""

    def __init__(
        self,
        path: Path,
        name: str = "",
        sector_size: int = 4096,
    ) -> None:
        if sector_size <= 0:
            raise ValueError("sector_size must be positive")
        self._path = path
        self._name = name or "spi_flash"
        self._sector_size = sector_size
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

        self.total_size: int = self._size
        self.sfdp_detected: bool = False
        self._probe_sfdp()

    # ------------------------------------------------------------------
    # SFDP probing
    # ------------------------------------------------------------------

    def _probe_sfdp(self) -> None:
        if self._mmap is None or self._size < 8:
            return
        try:
            head = bytes(self._mmap[0:8])
        except Exception:
            return
        if not head.startswith(_SFDP_SIGNATURE):
            return
        self.sfdp_detected = True
        # SFDP Basic Flash Parameter Table, 2nd DWORD (byte offset 0x04 of the
        # table) gives the flash density: if bit 31 == 0, it's flash_size-1
        # in bits; if bit 31 == 1, the remaining 31 bits encode
        # 2**(N) bits of density. The BFPT itself is pointed at by a PTP in
        # the SFDP header; we take a conservative shortcut and look for the
        # density DWORD at offset 0x34 (typical BFPT location when the SFDP
        # header is immediately followed by the first parameter table).
        if self._size < 0x38:
            return
        try:
            density = struct.unpack_from("<I", self._mmap, 0x34)[0]
        except struct.error:
            return
        if density == 0 or density == 0xFFFFFFFF:
            return
        if density & 0x80000000:
            # 2**(bits-except-MSB) bits.
            n = density & 0x7FFFFFFF
            if n < 64:
                bits = 1 << n
                self.total_size = bits // 8
        else:
            bits = density + 1
            if bits > 0:
                self.total_size = bits // 8

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
        raise NotImplementedError("SPIFlashLayer is read-only")

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
    def sector_size(self) -> int:
        return self._sector_size

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

    def __enter__(self) -> SPIFlashLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
