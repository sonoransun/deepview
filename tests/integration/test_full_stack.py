"""End-to-end composition walkthrough for the Deep View storage stack.

Exercises the full layer-wrapping chain from the plan "Composition walkthrough"
section (serene-sleeping-starlight.md):

    raw_nand -> ECCDataLayer(Hamming) -> LinearizedFlashLayer(BadBlockRemap)
           -> PartitionLayer -> FATFilesystem -> file bytes

Plus standalone smoke tests that prove the other per-slice primitives compose
with the shared ``DataLayer`` contract:

    * MBR ``parse_partitions`` + ``PartitionLayer.read`` round-trip.
    * ``DecryptedVolumeLayer`` AES-XTS round-trip against a known key.
    * ``OffloadEngine`` dispatch of a PBKDF2-SHA256 job through the process
      backend, compared against ``hashlib.pbkdf2_hmac``.

Every test guards its slice-specific imports with ``pytest.importorskip`` so a
core install that happens to be missing a downstream slice does not break the
integration suite.
"""
from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Callable, Iterator

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


# ---------------------------------------------------------------------------
# Shared in-memory DataLayer shim
# ---------------------------------------------------------------------------


class _MemoryDataLayer(DataLayer):
    """Minimal in-memory :class:`DataLayer` used by every test in this module."""

    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._buf = bytearray(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0:
            return b"\x00" * length if pad else b""
        end = min(offset + length, len(self._buf))
        out = bytes(self._buf[offset:end])
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        if offset < 0 or offset + len(data) > len(self._buf):
            raise ValueError("write out of bounds")
        self._buf[offset:offset + len(data)] = data

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._buf)

    def scan(
        self,
        scanner: object,
        progress_callback: Callable[..., None] | None = None,
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._buf) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name)

    def flip_bit(self, byte_offset: int, bit: int) -> None:
        """Flip a single bit in the underlying buffer (test helper)."""
        self._buf[byte_offset] ^= 1 << bit


# ---------------------------------------------------------------------------
# FAT12 image builder (mirrors tests/unit/test_storage/test_filesystems/test_fat_native.py)
# ---------------------------------------------------------------------------


_SECTOR = 512
_TOTAL_SECTORS = 12
_NUM_FATS = 1
_SECTORS_PER_FAT = 2
_RESERVED = 1
_ROOT_ENTRIES = 64
_SECTORS_PER_CLUSTER = 1
_FAT_PAYLOAD = b"hello world\n"


def _build_boot_sector() -> bytes:
    buf = bytearray(_SECTOR)
    buf[0:3] = b"\xEB\x3C\x90"
    buf[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", buf, 11, _SECTOR)
    buf[13] = _SECTORS_PER_CLUSTER
    struct.pack_into("<H", buf, 14, _RESERVED)
    buf[16] = _NUM_FATS
    struct.pack_into("<H", buf, 17, _ROOT_ENTRIES)
    struct.pack_into("<H", buf, 19, _TOTAL_SECTORS)
    buf[21] = 0xF8
    struct.pack_into("<H", buf, 22, _SECTORS_PER_FAT)
    struct.pack_into("<H", buf, 24, 1)
    struct.pack_into("<H", buf, 26, 1)
    struct.pack_into("<I", buf, 28, 0)
    struct.pack_into("<I", buf, 32, 0)
    buf[36] = 0x80
    buf[38] = 0x29
    struct.pack_into("<I", buf, 39, 0xDEADBEEF)
    buf[43:54] = b"TESTVOL    "
    buf[54:62] = b"FAT12   "
    buf[510] = 0x55
    buf[511] = 0xAA
    return bytes(buf)


def _build_fat12(entries: dict[int, int]) -> bytes:
    fat = bytearray(_SECTORS_PER_FAT * _SECTOR)
    entries.setdefault(0, 0xFF8)
    entries.setdefault(1, 0xFFF)
    for cluster, value in entries.items():
        off = (cluster * 3) // 2
        if cluster & 1:
            lo = fat[off] & 0x0F
            fat[off] = lo | ((value & 0x0F) << 4)
            fat[off + 1] = (value >> 4) & 0xFF
        else:
            fat[off] = value & 0xFF
            hi = fat[off + 1] & 0xF0
            fat[off + 1] = hi | ((value >> 8) & 0x0F)
    return bytes(fat)


def _build_dir_entry(name_8: str, ext_3: str, *, start_cluster: int, size: int) -> bytes:
    buf = bytearray(32)
    buf[0:8] = name_8.ljust(8)[:8].encode("ascii").upper()
    buf[8:11] = ext_3.ljust(3)[:3].encode("ascii").upper()
    buf[11] = 0x20  # archive attr
    struct.pack_into("<H", buf, 26, start_cluster & 0xFFFF)
    struct.pack_into("<H", buf, 20, (start_cluster >> 16) & 0xFFFF)
    struct.pack_into("<I", buf, 28, size)
    return bytes(buf)


def _build_fat_image() -> bytes:
    img = bytearray(_TOTAL_SECTORS * _SECTOR)
    img[0:_SECTOR] = _build_boot_sector()
    fat_bytes = _build_fat12({2: 0xFFF})
    img[_RESERVED * _SECTOR:(_RESERVED + _SECTORS_PER_FAT) * _SECTOR] = fat_bytes
    root_start = (_RESERVED + _NUM_FATS * _SECTORS_PER_FAT) * _SECTOR
    entry = _build_dir_entry("HELLO", "TXT", start_cluster=2, size=len(_FAT_PAYLOAD))
    img[root_start:root_start + 32] = entry
    data_start = root_start + 4 * _SECTOR
    img[data_start:data_start + len(_FAT_PAYLOAD)] = _FAT_PAYLOAD
    return bytes(img)


# ---------------------------------------------------------------------------
# NAND dump builder — page_size=512, spare_size=64, two 256-byte Hamming chunks.
# ---------------------------------------------------------------------------


_PAGE_SIZE = 512
_SPARE_SIZE = 64
_CHUNK = 256
_ECC_PER_CHUNK = 3
_CHUNKS_PER_PAGE = _PAGE_SIZE // _CHUNK
_ECC_TOTAL = _CHUNKS_PER_PAGE * _ECC_PER_CHUNK  # 6


def _build_nand_with_fat(fat_image: bytes) -> tuple[bytes, int]:
    """Lay the FAT image out across NAND pages + per-chunk Hamming ECC.

    Each physical page is: ``[data:512][ecc:6][padding:58]`` — the padding is
    sized to reach ``spare_size=64`` and is ignored by ``ECCDataLayer``.

    Returns ``(buffer, pages)`` where ``pages`` is the number of physical pages
    the FAT image was spread across (exactly ``len(fat_image) / 512``).
    """
    from deepview.storage.ecc.hamming import HammingDecoder

    decoder = HammingDecoder()
    assert len(fat_image) % _PAGE_SIZE == 0
    pages = len(fat_image) // _PAGE_SIZE

    out = bytearray()
    for page_idx in range(pages):
        data = fat_image[page_idx * _PAGE_SIZE:(page_idx + 1) * _PAGE_SIZE]
        ecc_blob = bytearray()
        for chunk_idx in range(_CHUNKS_PER_PAGE):
            chunk = data[chunk_idx * _CHUNK:(chunk_idx + 1) * _CHUNK]
            ecc_blob.extend(decoder.encode(chunk))
        spare = bytearray(_SPARE_SIZE)
        spare[:_ECC_TOTAL] = ecc_blob
        out.extend(data)
        out.extend(spare)
    return bytes(out), pages


def _byte_offset_for_page_data(page_idx: int) -> int:
    """Physical byte offset of the first data byte of page *page_idx*."""
    return page_idx * (_PAGE_SIZE + _SPARE_SIZE)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_raw_nand_through_fat() -> None:
    """raw NAND -> Hamming ECC -> linearized FTL -> PartitionLayer -> FAT12."""
    pytest.importorskip("deepview.storage.ecc.hamming")
    pytest.importorskip("deepview.storage.ecc.base")
    pytest.importorskip("deepview.storage.ftl.linearized")
    pytest.importorskip("deepview.storage.ftl.badblock")
    pytest.importorskip("deepview.storage.filesystems.fat_native")

    from deepview.storage.ecc.base import ECCDataLayer
    from deepview.storage.ecc.hamming import HammingDecoder
    from deepview.storage.filesystems.fat_native import FATFilesystem
    from deepview.storage.ftl.badblock import BadBlockRemapTranslator
    from deepview.storage.ftl.linearized import LinearizedFlashLayer
    from deepview.storage.geometry import NANDGeometry, SpareLayout, SpareRegion
    from deepview.storage.partition import PartitionLayer

    fat_image = _build_fat_image()
    nand_buf, pages = _build_nand_with_fat(fat_image)
    # Use a block shape that exactly covers every page with no bad blocks.
    assert pages == _TOTAL_SECTORS  # 12
    pages_per_block = 4
    blocks = pages // pages_per_block
    assert blocks * pages_per_block == pages

    spare_layout = SpareLayout(
        name="integration_ecc",
        spare_size=_SPARE_SIZE,
        regions=(
            SpareRegion(offset=0, length=_ECC_TOTAL, kind="ecc"),
            SpareRegion(
                offset=_ECC_TOTAL,
                length=_SPARE_SIZE - _ECC_TOTAL,
                kind="metadata",
            ),
        ),
    )
    geometry = NANDGeometry(
        page_size=_PAGE_SIZE,
        spare_size=_SPARE_SIZE,
        pages_per_block=pages_per_block,
        blocks=blocks,
        spare_layout=spare_layout,
    )

    # Inject one correctable bit flip per physical page *before* wrapping so
    # the ECC decoder exercises its SEC path during the FAT read below.
    memory = _MemoryDataLayer(nand_buf, name="raw_nand")
    for page_idx in range(pages):
        data_base = _byte_offset_for_page_data(page_idx)
        # Flip a different byte/bit per page; stay inside chunk 0 so each
        # page's flip lands on the 256-byte window its first ECC triple covers.
        flip_byte = data_base + (page_idx % _CHUNK)
        flip_bit = page_idx % 8
        memory.flip_bit(flip_byte, flip_bit)

    ecc_layer = ECCDataLayer(memory, HammingDecoder(), geometry)
    ftl = BadBlockRemapTranslator(geometry, bad_blocks=set())
    linearized = LinearizedFlashLayer(ecc_layer, ftl, geometry)
    assert linearized.maximum_address == len(fat_image) - 1

    partition = PartitionLayer(linearized, offset=0, size=len(fat_image))
    fs = FATFilesystem(partition)

    entries = list(fs.list("/"))
    assert len(entries) == 1
    assert entries[0].path == "/HELLO.TXT"
    assert entries[0].size == len(_FAT_PAYLOAD)

    assert fs.read("/HELLO.TXT") == _FAT_PAYLOAD

    # Every page should have contributed at least one ECC correction.
    stats = ecc_layer.error_stats()
    assert stats["corrected"] >= pages
    assert stats["uncorrectable"] == 0


@pytest.mark.integration
def test_partition_table_parsing() -> None:
    """Hand-crafted MBR disk -> ``parse_partitions`` -> ``PartitionLayer`` read."""
    pytest.importorskip("deepview.storage.partition")

    from deepview.storage.partition import PartitionLayer, parse_partitions

    sector_size = 512
    part_lba = 2048  # 1 MiB
    part_sectors = 2  # 1 KiB partition
    part_offset = part_lba * sector_size
    part_size = part_sectors * sector_size
    total_size = part_offset + part_size

    disk = bytearray(total_size)
    # MBR boot sector at LBA 0 with one Linux partition entry (type 0x83).
    mbr = bytearray(sector_size)
    mbr[510] = 0x55
    mbr[511] = 0xAA
    entry = bytearray(16)
    entry[0] = 0x00  # non-bootable
    entry[4] = 0x83  # Linux
    struct.pack_into("<I", entry, 8, part_lba)
    struct.pack_into("<I", entry, 12, part_sectors)
    mbr[446:446 + 16] = entry
    disk[0:sector_size] = mbr

    # Known contents inside the partition so the read-back is deterministic.
    payload = b"PART-IN-PLACE:" + bytes(range(32))
    disk[part_offset:part_offset + len(payload)] = payload

    layer = _MemoryDataLayer(bytes(disk), name="mbr_disk")
    parts = parse_partitions(layer)
    assert len(parts) == 1
    part = parts[0]
    assert part.scheme == "mbr"
    assert part.type_id == "0x83"
    assert part.start_offset == part_offset
    assert part.size == part_size

    slice_layer = PartitionLayer(layer, part.start_offset, part.size)
    assert slice_layer.read(0, 16) == payload[:16]
    assert slice_layer.read(14, 4) == payload[14:18]


@pytest.mark.integration
def test_decrypted_volume_layer_roundtrip() -> None:
    """AES-XTS encrypt 4 sectors with ``cryptography``, read them back via the layer."""
    pytest.importorskip("cryptography")
    pytest.importorskip("deepview.storage.containers.layer")

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from deepview.storage.containers.layer import DecryptedVolumeLayer

    sector_size = 512
    num_sectors = 4
    # Deterministic known plaintext: sector N is filled with (N,N+1,N+2,...) mod 256.
    plaintext = bytearray(num_sectors * sector_size)
    for sector in range(num_sectors):
        base = sector * sector_size
        plaintext[base:base + sector_size] = bytes(
            ((sector * 0x10 + i) & 0xFF) for i in range(sector_size)
        )
    # 64-byte AES-256-XTS key (two 32-byte halves concatenated).
    key = bytes(range(64))

    ciphertext = bytearray()
    for sector in range(num_sectors):
        tweak = sector.to_bytes(16, "little")
        encryptor = Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor()
        block = bytes(plaintext[sector * sector_size:(sector + 1) * sector_size])
        ciphertext.extend(encryptor.update(block) + encryptor.finalize())
    assert len(ciphertext) == num_sectors * sector_size

    backing = _MemoryDataLayer(bytes(ciphertext), name="xts_blob")
    layer = DecryptedVolumeLayer(
        backing,
        cipher_name="aes",
        key=key,
        sector_size=sector_size,
        data_offset=0,
        data_length=num_sectors * sector_size,
        mode="xts",
        iv_mode="tweak",
    )

    for sector in range(num_sectors):
        got = layer.read(sector * sector_size, sector_size)
        want = bytes(plaintext[sector * sector_size:(sector + 1) * sector_size])
        assert got == want, f"sector {sector} decrypt mismatch"

    # Cross-sector read spanning sectors 1..2 should also work.
    cross = layer.read(sector_size - 4, 8)
    assert cross == bytes(plaintext[sector_size - 4:sector_size + 4])


@pytest.mark.integration
def test_offload_pbkdf2_roundtrip() -> None:
    """ProcessPoolBackend dispatch of a PBKDF2-SHA256 job equals stdlib output."""
    pytest.importorskip("deepview.offload.engine")
    pytest.importorskip("deepview.offload.kdf")

    from deepview.core.context import AnalysisContext
    from deepview.offload.jobs import OffloadResult, make_job

    ctx = AnalysisContext.for_testing()
    engine = ctx.offload
    try:
        payload = {
            "password": b"hunter2",
            "salt": b"NaCl1234",
            "iterations": 1000,
            "dklen": 32,
        }
        job = make_job(
            kind="pbkdf2_sha256",
            payload=payload,
            callable_ref="deepview.offload.kdf:pbkdf2_sha256",
        )
        future = engine.submit(job, backend="process")
        # Bound the wait so a broken backend fails fast instead of hanging CI.
        timeout_s = float(os.environ.get("DEEPVIEW_OFFLOAD_TEST_TIMEOUT", "30"))
        result = future.await_result(timeout=timeout_s)
    finally:
        engine.shutdown(wait=True)

    assert isinstance(result, OffloadResult)
    assert result.ok is True, f"offload job failed: {result.error}"
    assert result.backend == "process"
    assert result.output == hashlib.pbkdf2_hmac(
        "sha256", b"hunter2", b"NaCl1234", 1000, 32
    )
