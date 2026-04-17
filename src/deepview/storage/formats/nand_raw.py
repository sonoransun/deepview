"""Raw NAND dump DataLayer.

A raw NAND image is the byte-for-byte output of reading a chip's pages with
their spare (OOB) areas interleaved: ``[data page 0][spare 0][data 1][spare 1]
...``. This layer exposes the whole interleaved stream via :meth:`read` and,
when a :class:`NANDGeometry` is supplied, also yields structured
:class:`PhysicalPage` records via :meth:`iter_pages`.

ECC decoding and FTL linearisation are deliberately *not* performed here —
they are the responsibility of the wrapping ``ECCDataLayer`` / FTL layers
(see :mod:`deepview.storage.ecc` and :mod:`deepview.storage.ftl`).
"""
from __future__ import annotations

import mmap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.ftl import PhysicalPage
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry
from deepview.storage.manager import StorageError

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class RawNANDLayer(DataLayer):
    """Flat NAND chip dump with optional page/spare geometry.

    When *geometry* is ``None`` the layer behaves as an opaque flat byte
    stream — useful for a first-pass dump of unknown provenance. Once the
    page/spare layout is known, pass a :class:`NANDGeometry` to enable
    :meth:`iter_pages`.
    """

    def __init__(
        self,
        path: Path,
        geometry: NANDGeometry | None,
        name: str = "",
    ) -> None:
        self._path = path
        self._geometry = geometry
        self._name = name or "nand_raw"
        self._size = path.stat().st_size
        self._file: BinaryIO | None = open(path, "rb")
        self._mmap: mmap.mmap | None = None
        if self._size > 0:
            # mmap with length 0 maps the whole file (read-only).
            self._mmap = mmap.mmap(
                self._file.fileno(), 0, access=mmap.ACCESS_READ
            )

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if offset < 0 or offset >= self._size:
            if pad:
                return b"\x00" * length
            return b""
        end = min(offset + length, self._size)
        if self._mmap is None:
            return b"\x00" * length if pad else b""
        data = bytes(self._mmap[offset:end])
        if pad and len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("RawNANDLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return offset >= 0 and length >= 0 and offset + length <= self._size

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        if self._mmap is None or self._size == 0:
            return
        chunk_size = 4 * 1024 * 1024  # 4 MiB
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
    # DataLayer properties
    # ------------------------------------------------------------------

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        # Highest valid address is the last addressable byte.
        return max(self._size - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    # ------------------------------------------------------------------
    # NAND-specific API
    # ------------------------------------------------------------------

    @property
    def geometry(self) -> NANDGeometry | None:
        return self._geometry

    def iter_pages(self) -> Iterator[tuple[PhysicalPage, bytes, bytes]]:
        """Yield ``(PhysicalPage, data_bytes, spare_bytes)`` for every page.

        Requires a :class:`NANDGeometry` to have been supplied at
        construction time. If the file is shorter than the declared total
        size, iteration stops cleanly at the last complete page in the
        dump (partial trailing pages are skipped).
        """
        geom = self._geometry
        if geom is None:
            raise StorageError(
                "RawNANDLayer.iter_pages requires a NANDGeometry; the layer "
                "was constructed in flat-file mode"
            )
        total_page = geom.total_page_size
        if total_page <= 0 or geom.page_size <= 0:
            raise StorageError("NANDGeometry has non-positive page sizes")
        pages_per_block = geom.pages_per_block
        for index in range(geom.total_pages):
            base = index * total_page
            if base + total_page > self._size:
                break
            data_offset = base
            spare_offset = base + geom.page_size
            if pages_per_block > 0:
                block = index // pages_per_block
                page_in_block = index % pages_per_block
            else:
                block = 0
                page_in_block = index
            meta = PhysicalPage(
                block=block,
                page=page_in_block,
                data_offset=data_offset,
                spare_offset=spare_offset,
                data_size=geom.page_size,
                spare_size=geom.spare_size,
            )
            # Use read() so the in-memory + flat-file paths share code.
            data = self.read(data_offset, geom.page_size)
            spare = self.read(spare_offset, geom.spare_size)
            yield meta, data, spare

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._mmap is not None:
            try:
                self._mmap.close()
            except ValueError:
                pass  # already closed
            self._mmap = None
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def __enter__(self) -> RawNANDLayer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
