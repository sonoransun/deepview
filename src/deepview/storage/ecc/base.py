"""ECC-aware DataLayer: transparently decodes raw NAND pages on read."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.ecc import ECCDecoder
from deepview.interfaces.layer import DataLayer
from deepview.storage.geometry import NANDGeometry

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class ECCDataLayer(DataLayer):
    """Wraps a raw NAND ``DataLayer`` with per-page ECC decode.

    Semantics:
        * The backing layer exposes every physical page (data + spare)
          laid out sequentially: page ``i`` spans physical offsets
          ``i * total_page_size`` .. ``(i + 1) * total_page_size - 1``.
        * This layer exposes *only* the data portion as a flat logical
          address space of length ``total_pages * page_size``.
        * Every read walks the physical pages it intersects, extracts
          the data slice and the ECC slice (from the spare-layout
          regions of kind ``"ecc"``), calls ``decoder.decode``, and
          appends the corrected bytes.
        * Stats accumulate across the lifetime of this layer instance.

    Writes are not supported: reintroducing ECC would require re-encoding
    + flushing a whole page and the forensic workflow is read-only.
    """

    def __init__(
        self,
        backing: DataLayer,
        decoder: ECCDecoder,
        geometry: NANDGeometry,
    ) -> None:
        self._backing = backing
        self._decoder = decoder
        self._geometry = geometry
        if geometry.spare_layout is None:
            raise ValueError(
                "ECCDataLayer requires geometry.spare_layout to be set"
            )
        ecc_regions = geometry.spare_layout.regions_of("ecc")
        if not ecc_regions:
            raise ValueError(
                "ECCDataLayer requires at least one spare region of kind='ecc'"
            )
        self._ecc_regions = ecc_regions
        # Total number of ECC bytes available per page (sum of all ecc regions).
        self._ecc_span = sum(r.length for r in ecc_regions)
        # How many data chunks does each page cover?
        if geometry.page_size % decoder.data_chunk != 0:
            raise ValueError(
                f"page_size {geometry.page_size} is not a multiple of decoder "
                f"data_chunk {decoder.data_chunk}"
            )
        self._chunks_per_page = geometry.page_size // decoder.data_chunk
        expected_ecc_per_page = self._chunks_per_page * decoder.ecc_bytes
        if expected_ecc_per_page > self._ecc_span:
            raise ValueError(
                f"spare layout exposes {self._ecc_span} ECC bytes per page but "
                f"decoder needs {expected_ecc_per_page}"
            )
        self._stats: dict[str, int] = {
            "corrected": 0,
            "uncorrectable": 0,
            "pages_read": 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_page_data(self, page_index: int) -> bytes:
        """Fetch physical page ``page_index``, decode every ECC chunk,
        return the corrected data portion (page_size bytes)."""
        g = self._geometry
        phys_offset = page_index * g.total_page_size
        raw = self._backing.read(phys_offset, g.total_page_size, pad=True)
        data_part = raw[: g.page_size]
        spare_part = raw[g.page_size:]

        # Concatenate every ECC region into a single contiguous span in
        # the order declared by the spare layout. Each chunk's ECC is a
        # slice of length decoder.ecc_bytes from this span.
        ecc_blob = bytearray()
        for region in self._ecc_regions:
            ecc_blob.extend(spare_part[region.offset:region.offset + region.length])

        chunk = self._decoder.data_chunk
        ecc_per = self._decoder.ecc_bytes
        out = bytearray()
        for i in range(self._chunks_per_page):
            data_slice = data_part[i * chunk:(i + 1) * chunk]
            ecc_slice = bytes(ecc_blob[i * ecc_per:(i + 1) * ecc_per])
            result = self._decoder.decode(data_slice, ecc_slice)
            out.extend(result.data)
            if result.uncorrectable:
                self._stats["uncorrectable"] += 1
            else:
                self._stats["corrected"] += result.errors_corrected
        self._stats["pages_read"] += 1
        return bytes(out)

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length <= 0:
            return b""
        total_data = self._total_data_bytes
        if offset < 0 or offset >= total_data:
            if pad:
                return b"\x00" * length
            raise ValueError(
                f"read offset {offset} outside logical range [0, {total_data})"
            )
        if offset + length > total_data:
            if pad:
                valid_len = total_data - offset
                valid = self._read_logical(offset, valid_len)
                return valid + b"\x00" * (length - valid_len)
            raise ValueError(
                f"read spans past end: offset={offset} length={length} "
                f"total={total_data}"
            )
        return self._read_logical(offset, length)

    def _read_logical(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes from logical offset ``offset`` (no bounds pad)."""
        page_size = self._geometry.page_size
        out = bytearray()
        remaining = length
        pos = offset
        while remaining > 0:
            page_idx = pos // page_size
            page_off = pos % page_size
            page_data = self._read_page_data(page_idx)
            take = min(remaining, page_size - page_off)
            out.extend(page_data[page_off:page_off + take])
            pos += take
            remaining -= take
        return bytes(out)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("ECCDataLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        end = offset + length
        return end <= self._total_data_bytes

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        total = self._geometry.total_pages
        for page_idx in range(total):
            try:
                data = self._read_page_data(page_idx)
            except Exception:
                continue
            logical_offset = page_idx * self._geometry.page_size
            for result in scanner.scan(data, offset=logical_offset):
                yield result
            if progress_callback and total > 0:
                progress_callback(page_idx / total)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def _total_data_bytes(self) -> int:
        return self._geometry.total_pages * self._geometry.page_size

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, self._total_data_bytes - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=f"ecc:{self._decoder.name}",
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )

    # ------------------------------------------------------------------
    # Extras
    # ------------------------------------------------------------------

    def error_stats(self) -> dict[str, int]:
        """Return a dict with keys ``corrected``, ``uncorrectable``, ``pages_read``."""
        return dict(self._stats)
