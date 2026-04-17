from __future__ import annotations

import struct
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Partition:
    """A discovered partition slice on a disk-image-shaped DataLayer."""

    index: int
    scheme: str  # "mbr" | "gpt"
    type_id: str  # MBR type byte hex (e.g. "0x83") or GPT type GUID
    name: str
    start_offset: int
    size: int
    boot: bool = False
    uuid: str | None = None  # GPT partition UUID

    @property
    def end_offset(self) -> int:
        return self.start_offset + self.size


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _parse_mbr(layer: DataLayer) -> list[Partition]:
    """Parse a classic MBR partition table at sector 0."""
    sector = layer.read(0, 512)
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
        return []
    out: list[Partition] = []
    for i in range(4):
        base = 446 + i * 16
        entry = sector[base : base + 16]
        boot = entry[0]
        type_byte = entry[4]
        if type_byte == 0:
            continue
        lba_start = struct.unpack_from("<I", entry, 8)[0]
        sectors = struct.unpack_from("<I", entry, 12)[0]
        out.append(
            Partition(
                index=i,
                scheme="mbr",
                type_id=f"0x{type_byte:02x}",
                name=f"mbr{i}",
                start_offset=lba_start * 512,
                size=sectors * 512,
                boot=bool(boot & 0x80),
            )
        )
    return out


_GPT_SIGNATURE = b"EFI PART"


def _parse_gpt(layer: DataLayer) -> list[Partition]:
    """Parse a GPT header at LBA 1 (offset 512)."""
    header = layer.read(512, 92)
    if len(header) < 92 or header[:8] != _GPT_SIGNATURE:
        return []
    part_entries_lba = struct.unpack_from("<Q", header, 72)[0]
    num_entries = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    if entry_size < 128 or num_entries == 0:
        return []
    table_offset = part_entries_lba * 512
    table_bytes = layer.read(table_offset, num_entries * entry_size)
    out: list[Partition] = []
    for i in range(num_entries):
        e = table_bytes[i * entry_size : (i + 1) * entry_size]
        type_guid_bytes = e[:16]
        if type_guid_bytes == b"\x00" * 16:
            continue
        unique_guid_bytes = e[16:32]
        first_lba = struct.unpack_from("<Q", e, 32)[0]
        last_lba = struct.unpack_from("<Q", e, 40)[0]
        name = e[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        out.append(
            Partition(
                index=i,
                scheme="gpt",
                type_id=str(_guid_from_bytes(type_guid_bytes)),
                name=name or f"gpt{i}",
                start_offset=first_lba * 512,
                size=(last_lba - first_lba + 1) * 512,
                uuid=str(_guid_from_bytes(unique_guid_bytes)),
            )
        )
    return out


def _guid_from_bytes(b: bytes) -> uuid.UUID:
    """GPT GUIDs are mixed-endian: first 3 fields little-endian, last 8 bytes big-endian."""
    return uuid.UUID(bytes_le=b)


def parse_partitions(layer: DataLayer) -> list[Partition]:
    """Detect and return all partitions on *layer*.

    Tries GPT first (more authoritative), then MBR. A "protective MBR" preceding
    a GPT is detected and ignored when GPT is present.
    """
    gpt = _parse_gpt(layer)
    if gpt:
        return gpt
    return _parse_mbr(layer)


# ---------------------------------------------------------------------------
# Layer wrapper
# ---------------------------------------------------------------------------


class PartitionLayer(DataLayer):
    """A DataLayer slice over a backing layer, bounded by ``[offset, offset+size)``.

    Composes with any other DataLayer (raw, ECC-corrected, FTL-linearized, decrypted
    container, etc.) so a typical stack reads:

        raw -> ECCDataLayer -> LinearizedFlashLayer -> PartitionLayer -> Filesystem
    """

    def __init__(
        self,
        backing: DataLayer,
        offset: int,
        size: int,
        name: str = "",
    ) -> None:
        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        self._backing = backing
        self._offset = offset
        self._size = size
        self._name = name or f"partition@{offset:#x}"

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset >= self._size:
            if pad:
                return b"\x00" * length
            raise ValueError(f"offset {offset:#x} beyond partition size {self._size:#x}")
        clipped = min(length, self._size - offset)
        data = self._backing.read(self._offset + offset, clipped, pad=pad)
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("PartitionLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length < 0:
            return False
        return offset + length <= self._size

    def scan(
        self,
        scanner: object,
        progress_callback: Callable[..., None] | None = None,
    ) -> Iterator[ScanResult]:
        # Delegate to the scanner's protocol; the partition is just bytes.
        scan_method = getattr(scanner, "scan", None)
        if scan_method is None:
            return iter(())
        return scan_method(self, progress_callback=progress_callback)

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
            minimum_address=0,
            maximum_address=self.maximum_address,
        )
