"""Compose the full NAND storage stack end-to-end.

Builds a synthetic raw NAND dump in memory (interleaved data+spare with
a valid SmartMedia Hamming ECC per page), then layers:

    RawNANDLayer
      -> ECCDataLayer (Hamming)
        -> PartitionLayer (manual)
          -> FAT12 filesystem
            -> read a file

This is the full composition walkthrough from the plan and the single
best demonstration that :class:`DataLayer` is a genuine abstraction that
wraps and composes.

Usage:
    python examples/02_compose_nand_stack.py
    python examples/02_compose_nand_stack.py --flip-bit  # inject a single-bit
                                                         # error so ECC has
                                                         # something to correct

Requires no optional extras; the FAT12 adapter and the Hamming decoder
are pure Python.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from dataclasses import replace
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.storage.ecc.base import ECCDataLayer
from deepview.storage.ecc.hamming import HammingDecoder
from deepview.storage.formats.nand_raw import RawNANDLayer
from deepview.storage.geometry import NANDGeometry, SpareLayout
from deepview.storage.partition import PartitionLayer

from examples._synthetic import build_fat12_image, build_nand_dump


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--file", default="HELLO.TXT",
                        help="file inside the FAT12 image to read (default HELLO.TXT)")
    parser.add_argument("--flip-bit", action="store_true",
                        help="flip a bit in page 0 so ECCDataLayer has to correct it")
    args = parser.parse_args()

    # We build a FAT12 image that fits into exactly one NAND "payload".
    fat_bytes = build_fat12_image()
    page_size = 256
    spare_size = 16
    pages_per_block = 4
    # Choose a block count large enough to carry the whole FAT image.
    pages_needed = (len(fat_bytes) + page_size - 1) // page_size
    blocks = (pages_needed + pages_per_block - 1) // pages_per_block
    # Round up to at least 1 block, but keep geometry tiny.
    blocks = max(blocks, 1)

    nand_payload = fat_bytes
    nand_bytes = bytearray(
        build_nand_dump(
            page_size=page_size,
            spare_size=spare_size,
            pages_per_block=pages_per_block,
            blocks=blocks,
            payload=nand_payload,
        )
    )

    if args.flip_bit:
        # Flip a single data bit in page 0 — ECC must correct it.
        nand_bytes[0] ^= 0x02
        print("Injected a single-bit flip at physical offset 0 (bit 1).")

    # Write to a temp file because RawNANDLayer mmaps its input.
    fd, path_str = tempfile.mkstemp(prefix="deepview-nand-", suffix=".bin")
    os.close(fd)
    path = Path(path_str)
    path.write_bytes(bytes(nand_bytes))

    try:
        # ------------------------------------------------------------------
        # 1. RawNANDLayer — interleaved data+spare stream
        # ------------------------------------------------------------------
        geometry = NANDGeometry(
            page_size=page_size,
            spare_size=spare_size,
            pages_per_block=pages_per_block,
            blocks=blocks,
            spare_layout=SpareLayout.linear_ecc(spare_size=spare_size, ecc_bytes=3),
        )
        raw = RawNANDLayer(path, geometry=geometry, name="synthetic-nand")
        print(f"RawNANDLayer:     size={raw.maximum_address + 1} bytes, "
              f"pages={geometry.total_pages}")

        # ------------------------------------------------------------------
        # 2. ECCDataLayer — strips spare, decodes Hamming, exposes data-only
        # ------------------------------------------------------------------
        ecc = ECCDataLayer(raw, HammingDecoder(), geometry)
        print(f"ECCDataLayer:     logical size={ecc.maximum_address + 1}")

        # ------------------------------------------------------------------
        # 3. PartitionLayer — manually carve [0, len(fat)) so FAT12 sees only
        #    the portion containing its boot sector.
        # ------------------------------------------------------------------
        part = PartitionLayer(ecc, offset=0, size=len(fat_bytes), name="synthetic-fat")
        print(f"PartitionLayer:   {part.metadata.name} size={part.maximum_address + 1}")

        # ------------------------------------------------------------------
        # 4. Filesystem probe via StorageManager
        # ------------------------------------------------------------------
        ctx = AnalysisContext.for_testing()
        fs = ctx.storage.open_filesystem(part)
        print(f"Filesystem:       {fs.fs_name} block_size={fs.block_size}")

        # ------------------------------------------------------------------
        # 5. Walk the filesystem and read the requested file
        # ------------------------------------------------------------------
        print()
        print("Directory listing (root):")
        for entry in fs.list("/"):
            kind = "DIR" if entry.is_dir else "FILE"
            print(f"  [{kind}] {entry.path:<20} size={entry.size}")

        target = args.file
        try:
            data = fs.read(target)
        except Exception as exc:  # noqa: BLE001
            print(f"\nCould not read {target!r}: {exc}")
        else:
            print(f"\nContents of {target} ({len(data)} bytes):")
            try:
                print(data.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                print(repr(data[:120]))

        # ECC stats
        print("\nECC stats:", ecc.error_stats())
        raw.close()
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    return 0


# Silence an unused-import warning when flip-bit is off.
_ = replace


if __name__ == "__main__":
    raise SystemExit(main())
