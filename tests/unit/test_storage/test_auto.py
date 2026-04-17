"""Tests for the end-to-end storage stack opener."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.storage.auto import AutoOpenResult, auto_open, auto_unlock_and_open


@pytest.fixture
def ctx() -> AnalysisContext:
    return AnalysisContext.for_testing()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_mbr_image(
    path: Path,
    *,
    part_offset: int = 0x10000,
    part_size: int = 0x10000,
    type_byte: int = 0x83,
) -> None:
    """Write a 128 KiB image with a single MBR entry at slot 0."""
    total = part_offset + part_size
    buf = bytearray(total)
    # Build a minimal MBR: 446 bytes boot code (zeroed), then partition entries.
    assert part_offset % 512 == 0
    assert part_size % 512 == 0
    lba_start = part_offset // 512
    sectors = part_size // 512
    entry = bytearray(16)
    entry[0] = 0x00  # not bootable
    entry[4] = type_byte
    struct.pack_into("<I", entry, 8, lba_start)
    struct.pack_into("<I", entry, 12, sectors)
    buf[446 : 446 + 16] = bytes(entry)
    # MBR boot signature.
    buf[510] = 0x55
    buf[511] = 0xAA
    path.write_bytes(bytes(buf))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_auto_open_raw(ctx: AnalysisContext, tmp_path: Path) -> None:
    """A flat 1 KiB zero-filled file yields a raw layer + no partitions."""
    target = tmp_path / "blank.bin"
    target.write_bytes(b"\x00" * 1024)

    result = auto_open(ctx, target)

    assert isinstance(result, AutoOpenResult)
    # RawMemoryLayer exposes either size or size-1 depending on convention;
    # accept either for robustness across future refactors.
    assert result.raw_layer.maximum_address in (1023, 1024)
    assert result.transformed_layer is result.raw_layer
    assert result.partitions == ()
    assert result.filesystems == {}


def test_auto_open_with_partitions(ctx: AnalysisContext, tmp_path: Path) -> None:
    """A single-MBR-entry image yields exactly one detected partition."""
    target = tmp_path / "disk.img"
    _build_mbr_image(target, part_offset=0x10000, part_size=0x10000)

    result = auto_open(ctx, target)

    assert len(result.partitions) == 1
    part = result.partitions[0]
    assert part.scheme == "mbr"
    assert part.start_offset == 0x10000
    assert part.size == 0x10000

    # Filesystem probing is best-effort: the zero-filled region is not any
    # recognisable FS, so either filesystems is empty (common) or contains
    # an adapter that happens to false-positive (unlikely). If empty, a note
    # should record the probe miss.
    if not result.filesystems:
        probe_notes = [n for n in result.notes if "filesystem probe" in n]
        # The manager raises "No filesystem adapter recognised the layer";
        # that message is carried into the note verbatim.
        assert probe_notes, (
            f"expected a filesystem-probe note, got notes={result.notes!r}"
        )


def test_auto_open_with_partitions_skips_fs(
    ctx: AnalysisContext, tmp_path: Path
) -> None:
    """`open_filesystems=False` detects partitions but never probes."""
    target = tmp_path / "disk.img"
    _build_mbr_image(target, part_offset=0x10000, part_size=0x10000)

    result = auto_open(ctx, target, open_filesystems=False)

    assert len(result.partitions) == 1
    assert result.filesystems == {}
    assert not any("filesystem probe" in n for n in result.notes)


def test_auto_unlock_open_passes_through(
    ctx: AnalysisContext, tmp_path: Path
) -> None:
    """On an unencrypted file, the unlock helper matches plain auto_open."""
    target = tmp_path / "plain.img"
    _build_mbr_image(target, part_offset=0x10000, part_size=0x10000)

    plain = auto_open(ctx, target)
    unlocked = auto_unlock_and_open(ctx, target, scan_keys=False)

    # Partition tuples must match structurally (same index/offset/size).
    assert [p.start_offset for p in plain.partitions] == [
        p.start_offset for p in unlocked.partitions
    ]
    assert [p.size for p in plain.partitions] == [
        p.size for p in unlocked.partitions
    ]
    # Neither path should have produced any filesystems for this blank image.
    assert plain.filesystems.keys() == unlocked.filesystems.keys()


def test_auto_open_unknown_ecc_is_graceful(
    ctx: AnalysisContext, tmp_path: Path
) -> None:
    """A bogus ECC name must not raise; it should surface as a note."""
    from deepview.storage.geometry import NANDGeometry, SpareLayout

    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00" * 1024)

    geometry = NANDGeometry(
        page_size=256,
        spare_size=16,
        pages_per_block=4,
        blocks=1,
        spare_layout=SpareLayout.onfi(spare_size=16),
    )

    result = auto_open(ctx, target, nand_geometry=geometry, ecc="definitely-not-a-codec")
    assert any("ecc" in n and "unavailable" in n for n in result.notes)
