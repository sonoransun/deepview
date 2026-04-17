"""Shared helpers for the Deep View example scripts.

Everything here is stdlib-only so the examples that depend on no extras
(synthetic data) stay runnable out of the box. The main entry points:

* :func:`build_fat12_image` — construct a minimal, valid FAT12 filesystem
  image in memory and return the bytes.
* :func:`build_nand_dump` — build an interleaved raw NAND dump (data +
  spare) with a valid SmartMedia Hamming ECC in every page's spare area.
* :class:`BytesLayer` — an in-memory :class:`DataLayer` over a ``bytes``
  object, used by several examples as a stand-in for ``RawMemoryLayer``
  when we don't want to touch the filesystem.
"""
from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


# ---------------------------------------------------------------------------
# BytesLayer — in-memory DataLayer
# ---------------------------------------------------------------------------


class BytesLayer(DataLayer):
    """Minimal in-memory :class:`DataLayer` backed by a ``bytes`` buffer."""

    def __init__(self, buf: bytes, name: str = "bytes") -> None:
        self._buf = buf
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if offset < 0 or offset >= len(self._buf):
            return b"\x00" * length if pad else b""
        end = min(offset + length, len(self._buf))
        data = self._buf[offset:end]
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("BytesLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._buf)

    def scan(
        self,
        scanner: object,
        progress_callback: Callable[..., None] | None = None,
    ) -> Iterator[ScanResult]:
        method = getattr(scanner, "scan", None)
        if method is None:
            return iter(())
        return method(self._buf, offset=0)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._buf) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )


# ---------------------------------------------------------------------------
# FAT12 synthetic image
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FATFile:
    name: str  # 8.3 uppercase, no dot
    content: bytes


def _fat12_encode_name(name: str) -> bytes:
    """Encode an 8.3 filename into the 11-byte on-disk form."""
    if "." in name:
        base, ext = name.split(".", 1)
    else:
        base, ext = name, ""
    base = base.upper().ljust(8)[:8]
    ext = ext.upper().ljust(3)[:3]
    return (base + ext).encode("ascii")


def build_fat12_image(
    *,
    files: list[tuple[str, bytes]] | None = None,
    volume_label: str = "DEEPVIEW  ",
) -> bytes:
    """Build a tiny valid FAT12 image and return it as bytes.

    The image has a 512-byte/sector, 1-sector/cluster layout with 1 FAT,
    16 root directory entries, and 256 total sectors (128 KiB). Each
    file content is written into consecutive clusters starting at
    cluster 2.
    """
    if files is None:
        files = [
            ("HELLO.TXT", b"Hello, Deep View!\n"),
            ("README.MD", b"Synthetic FAT12 test image.\n"),
        ]

    bytes_per_sector = 512
    sectors_per_cluster = 1
    reserved_sectors = 1
    num_fats = 1
    root_entries = 16
    total_sectors = 256
    sectors_per_fat = 1
    cluster_size = bytes_per_sector * sectors_per_cluster

    img = bytearray(bytes_per_sector * total_sectors)

    # --- Boot sector -------------------------------------------------------
    boot = bytearray(bytes_per_sector)
    boot[0:3] = b"\xeb\x3c\x90"  # jmp
    boot[3:11] = b"DEEPVIEW"  # OEM
    struct.pack_into("<H", boot, 11, bytes_per_sector)
    boot[13] = sectors_per_cluster
    struct.pack_into("<H", boot, 14, reserved_sectors)
    boot[16] = num_fats
    struct.pack_into("<H", boot, 17, root_entries)
    struct.pack_into("<H", boot, 19, total_sectors)
    boot[21] = 0xF8  # media
    struct.pack_into("<H", boot, 22, sectors_per_fat)
    struct.pack_into("<H", boot, 24, 1)  # sectors per track
    struct.pack_into("<H", boot, 26, 1)  # heads
    boot[36:43] = volume_label.ljust(8)[:8].encode("ascii") + b"       "
    boot[43:54] = volume_label.ljust(11)[:11].encode("ascii")
    boot[54:62] = b"FAT12   "
    boot[510] = 0x55
    boot[511] = 0xAA
    img[0:bytes_per_sector] = boot

    # --- FAT and root dir location ----------------------------------------
    fat_start = reserved_sectors * bytes_per_sector
    root_dir_start = fat_start + num_fats * sectors_per_fat * bytes_per_sector
    root_dir_sectors = ((root_entries * 32) + bytes_per_sector - 1) // bytes_per_sector
    data_start = root_dir_start + root_dir_sectors * bytes_per_sector

    fat = bytearray(sectors_per_fat * bytes_per_sector)
    fat[0] = 0xF8
    fat[1] = 0xFF
    fat[2] = 0xFF

    def fat12_set(cluster: int, value: int) -> None:
        off = (cluster * 3) // 2
        if cluster & 1:
            fat[off] = (fat[off] & 0x0F) | ((value & 0x0F) << 4)
            fat[off + 1] = (value >> 4) & 0xFF
        else:
            fat[off] = value & 0xFF
            fat[off + 1] = (fat[off + 1] & 0xF0) | ((value >> 8) & 0x0F)

    # --- Layout files into clusters starting at 2 -------------------------
    root_dir = bytearray(root_dir_sectors * bytes_per_sector)
    next_cluster = 2
    for i, (name, content) in enumerate(files):
        nclusters = max(1, (len(content) + cluster_size - 1) // cluster_size)
        start_cluster = next_cluster
        for k in range(nclusters):
            c = start_cluster + k
            if k == nclusters - 1:
                fat12_set(c, 0xFFF)  # end of chain
            else:
                fat12_set(c, c + 1)
            cluster_offset = data_start + (c - 2) * cluster_size
            chunk = content[k * cluster_size : (k + 1) * cluster_size]
            img[cluster_offset : cluster_offset + len(chunk)] = chunk

        # Directory entry (32 bytes)
        entry = bytearray(32)
        entry[0:11] = _fat12_encode_name(name)
        entry[11] = 0x20  # archive
        struct.pack_into("<H", entry, 26, start_cluster & 0xFFFF)
        struct.pack_into("<I", entry, 28, len(content))
        root_dir[i * 32 : (i + 1) * 32] = entry
        next_cluster += nclusters

    img[fat_start : fat_start + len(fat)] = fat
    img[root_dir_start : root_dir_start + len(root_dir)] = root_dir

    return bytes(img)


# ---------------------------------------------------------------------------
# Synthetic NAND dump with Hamming ECC
# ---------------------------------------------------------------------------


def build_nand_dump(
    *,
    page_size: int = 256,
    spare_size: int = 16,
    pages_per_block: int = 4,
    blocks: int = 4,
    payload: bytes | None = None,
) -> bytes:
    """Build a raw NAND dump with interleaved data+spare and a valid Hamming
    ECC in every page's spare region.

    The SmartMedia Hamming decoder (:mod:`deepview.storage.ecc.hamming`)
    works on 256-byte chunks with 3 ECC bytes each — we keep page_size at
    256 so one chunk == one page. The ECC lives in the *last* three bytes
    of the spare, matching the ``SpareLayout.linear_ecc`` preset.
    """
    from deepview.storage.ecc.hamming import HammingDecoder

    total_pages = blocks * pages_per_block
    if payload is None:
        # Default payload fills all pages with "DEEPVIEW" pattern.
        payload = (b"DEEPVIEW" * ((page_size * total_pages) // 8 + 1))[
            : page_size * total_pages
        ]
    if len(payload) < page_size * total_pages:
        payload = payload + b"\x00" * (page_size * total_pages - len(payload))

    decoder = HammingDecoder()
    out = bytearray()
    for idx in range(total_pages):
        data = payload[idx * page_size : (idx + 1) * page_size]
        ecc = decoder.encode(data)
        spare = bytearray(spare_size)
        spare[0] = 0xFF  # bad-block marker (0xFF == good)
        spare[spare_size - 3 : spare_size] = ecc
        out.extend(data)
        out.extend(spare)
    return bytes(out)


__all__ = ["BytesLayer", "build_fat12_image", "build_nand_dump"]
