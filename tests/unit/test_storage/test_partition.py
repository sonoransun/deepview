"""Unit tests for :mod:`deepview.storage.partition`.

Covers MBR + GPT parsing edge cases and :class:`PartitionLayer` bounds /
read / write semantics. Uses the shared :mod:`_factories` builders so
byte-exact table construction stays in one place.
"""
from __future__ import annotations

import pytest

from tests._factories import (
    EFI_SYSTEM_TYPE,
    GPTEntry,
    LINUX_FS_TYPE,
    MBREntry,
    MemoryDataLayer,
    build_gpt,
    build_mbr,
)

from deepview.storage.partition import (
    PartitionLayer,
    _parse_gpt,
    _parse_mbr,
    parse_partitions,
)


# ---------------------------------------------------------------------------
# parse_partitions / _parse_mbr
# ---------------------------------------------------------------------------


def test_empty_disk_returns_no_partitions() -> None:
    layer = MemoryDataLayer(b"\x00" * 4096)
    assert parse_partitions(layer) == []


def test_mbr_single_linux_partition() -> None:
    mbr = build_mbr([(0x83, 2048, 2048)])
    layer = MemoryDataLayer(mbr + b"\x00" * 1024)
    parts = parse_partitions(layer)
    assert len(parts) == 1
    p = parts[0]
    assert p.scheme == "mbr"
    assert p.start_offset == 2048 * 512
    assert p.size == 2048 * 512
    assert p.type_id == "0x83"
    assert p.boot is False


def test_mbr_all_four_slots_populated_in_order() -> None:
    mbr = build_mbr(
        [
            (0x83, 2048, 2048),
            (0x07, 4096, 4096),
            (0x82, 8192, 2048),
            (0x0C, 10240, 2048),
        ]
    )
    # Pad backing so the GPT probe (reads offset 512) sees zeros, not OOB.
    layer = MemoryDataLayer(mbr + b"\x00" * 2048)
    parts = parse_partitions(layer)
    assert len(parts) == 4
    assert [p.index for p in parts] == [0, 1, 2, 3]
    assert [p.type_id for p in parts] == ["0x83", "0x07", "0x82", "0x0c"]
    assert [p.start_offset for p in parts] == [
        2048 * 512,
        4096 * 512,
        8192 * 512,
        10240 * 512,
    ]


def test_mbr_type_zero_slot_is_skipped() -> None:
    # Slot 1 has type 0 and must be dropped.
    mbr = build_mbr(
        [
            (0x83, 2048, 2048),
            (0x00, 4096, 4096),
            (0x82, 8192, 2048),
        ]
    )
    layer = MemoryDataLayer(mbr + b"\x00" * 2048)
    parts = parse_partitions(layer)
    assert len(parts) == 2
    assert [p.index for p in parts] == [0, 2]
    assert [p.type_id for p in parts] == ["0x83", "0x82"]


def test_mbr_boot_flag_is_surfaced() -> None:
    mbr = build_mbr(
        [MBREntry(type_byte=0x83, start_lba=2048, sector_count=2048, boot=True)]
    )
    layer = MemoryDataLayer(mbr + b"\x00" * 2048)
    parts = parse_partitions(layer)
    assert len(parts) == 1
    assert parts[0].boot is True


def test_mbr_missing_signature_returns_empty() -> None:
    mbr = bytearray(build_mbr([(0x83, 2048, 2048)]))
    # Strip the 0x55AA magic.
    mbr[510] = 0x00
    mbr[511] = 0x00
    layer = MemoryDataLayer(bytes(mbr) + b"\x00" * 2048)
    assert _parse_mbr(layer) == []
    assert parse_partitions(layer) == []


# ---------------------------------------------------------------------------
# _parse_gpt
# ---------------------------------------------------------------------------


def test_gpt_single_linux_partition() -> None:
    gpt = build_gpt([GPTEntry(LINUX_FS_TYPE, first_lba=34, last_lba=2081)])
    layer = MemoryDataLayer(gpt + b"\x00" * 1024)
    parts = parse_partitions(layer)
    assert len(parts) == 1
    p = parts[0]
    assert p.scheme == "gpt"
    assert p.start_offset == 34 * 512
    assert p.size == (2081 - 34 + 1) * 512
    assert p.type_id == str(LINUX_FS_TYPE)
    assert p.uuid is not None


def test_gpt_wins_over_hybrid_mbr() -> None:
    # Build a GPT image (sector 0 is a zero MBR placeholder inside build_gpt).
    gpt = bytearray(
        build_gpt([GPTEntry(EFI_SYSTEM_TYPE, first_lba=34, last_lba=2081)])
    )
    # Splice a valid MBR into sector 0 that declares a different partition.
    mbr_sector = build_mbr([(0x83, 2048, 2048)])
    gpt[: len(mbr_sector)] = mbr_sector
    layer = MemoryDataLayer(bytes(gpt))
    parts = parse_partitions(layer)
    # GPT must win — scheme should be gpt, not mbr.
    assert len(parts) == 1
    assert parts[0].scheme == "gpt"
    assert parts[0].type_id == str(EFI_SYSTEM_TYPE)


def test_gpt_zero_num_entries_returns_empty() -> None:
    gpt = bytearray(build_gpt([GPTEntry(LINUX_FS_TYPE, 34, 2081)]))
    # num_entries @ offset 512 + 80 = 592; overwrite with zero.
    gpt[592:596] = b"\x00\x00\x00\x00"
    layer = MemoryDataLayer(bytes(gpt))
    assert _parse_gpt(layer) == []


def test_gpt_entry_size_below_128_returns_empty() -> None:
    gpt = bytearray(build_gpt([GPTEntry(LINUX_FS_TYPE, 34, 2081)]))
    # entry_size @ offset 512 + 84 = 596; overwrite with 64 (too small).
    gpt[596:600] = (64).to_bytes(4, "little")
    layer = MemoryDataLayer(bytes(gpt))
    assert _parse_gpt(layer) == []


# ---------------------------------------------------------------------------
# PartitionLayer
# ---------------------------------------------------------------------------


@pytest.fixture
def partition_layer() -> tuple[PartitionLayer, bytes]:
    """A 2 KiB partition beginning at offset 1024 on a 4 KiB backing."""
    # Use recognisable marker bytes in the slice we expect to read.
    filler = b"\xaa" * 1024 + (b"\xbb" * 2048) + b"\xcc" * 1024
    backing = MemoryDataLayer(filler)
    return PartitionLayer(backing, offset=1024, size=2048), filler


def test_partition_layer_read_returns_slice(
    partition_layer: tuple[PartitionLayer, bytes],
) -> None:
    layer, backing_bytes = partition_layer
    assert layer.read(0, 4) == backing_bytes[1024:1028]
    assert layer.read(10, 16) == backing_bytes[1034:1050]


def test_partition_layer_read_past_end_raises(
    partition_layer: tuple[PartitionLayer, bytes],
) -> None:
    layer, _ = partition_layer
    with pytest.raises(ValueError):
        layer.read(layer.maximum_address + 1, 4)


def test_partition_layer_read_with_pad_zero_fills(
    partition_layer: tuple[PartitionLayer, bytes],
) -> None:
    layer, _ = partition_layer
    # Read starting inside the partition but extending beyond its end.
    result = layer.read(2046, 8, pad=True)
    assert len(result) == 8
    assert result[-4:] == b"\x00\x00\x00\x00"


def test_partition_layer_write_refused(
    partition_layer: tuple[PartitionLayer, bytes],
) -> None:
    layer, _ = partition_layer
    with pytest.raises(NotImplementedError):
        layer.write(0, b"nope")


def test_partition_layer_is_valid_respects_bounds(
    partition_layer: tuple[PartitionLayer, bytes],
) -> None:
    layer, _ = partition_layer
    assert layer.is_valid(0, 1) is True
    assert layer.is_valid(0, 2048) is True
    assert layer.is_valid(0, 2049) is False
    assert layer.is_valid(-1, 1) is False
    assert layer.is_valid(2048, 1) is False


def test_partition_layer_maximum_address(
    partition_layer: tuple[PartitionLayer, bytes],
) -> None:
    layer, _ = partition_layer
    assert layer.maximum_address == 2048 - 1


def test_partition_layer_zero_size_maximum_address() -> None:
    layer = PartitionLayer(MemoryDataLayer(b""), offset=0, size=0)
    assert layer.maximum_address == 0
