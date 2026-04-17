"""Captured GPU VRAM dump DataLayer.

The dump itself is a flat byte stream — whatever the acquisition tool wrote
(pycuda / ROCm runtime / Intel-level-zero). The vendor tag is carried purely
as metadata so plugins can dispatch vendor-specific post-processing (texture
decoding, shader-heap walking, etc.).

Live VRAM acquisition is explicitly out-of-scope for this layer; that belongs
to a future acquisition provider. We deliberately avoid any import of pycuda
or friends here so a core install without the ``gpu`` extra still imports
cleanly.
"""
from __future__ import annotations

import mmap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


Vendor = Literal["nvidia", "amd", "intel", "unknown"]


class GPUVRAMLayer(DataLayer):
    """Flat-passthrough VRAM dump with a vendor tag in metadata."""

    def __init__(
        self,
        path: Path,
        *,
        vendor: Vendor = "unknown",
        name: str = "",
    ) -> None:
        self._path = path
        self._vendor: Vendor = vendor
        self._name = name or f"gpu_vram:{vendor}"
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

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
        raise NotImplementedError("GPUVRAMLayer is read-only")

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
    def vendor(self) -> Vendor:
        return self._vendor

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

    def __enter__(self) -> GPUVRAMLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
