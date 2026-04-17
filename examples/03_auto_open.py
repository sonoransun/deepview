"""One-line auto-open of a forensic image.

:func:`deepview.storage.auto.auto_open` wires up format detection, the
raw :class:`DataLayer`, optional NAND ECC/FTL wrapping, partition
parsing, and per-partition filesystem probing in a single call. The
returned :class:`AutoOpenResult` bundles every artefact produced along
the way, plus a ``notes`` tuple that records any best-effort step that
failed.

Usage:
    python examples/03_auto_open.py /path/to/disk.img
    python examples/03_auto_open.py /path/to/nand.bin --ecc hamming \\
                                    --spare-layout linear

With no path given, a synthetic FAT12 image is auto-opened so the demo
is self-contained.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.storage.auto import auto_open
from deepview.storage.geometry import NANDGeometry

from examples._synthetic import build_fat12_image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("path", nargs="?", type=Path, help="forensic image path")
    parser.add_argument("--ecc", default=None,
                        help="ECC decoder name (hamming, bch, rs) when image is raw NAND")
    parser.add_argument("--ftl", default=None,
                        help="FTL translator name (ubi, jffs2, mtd, ...)")
    parser.add_argument("--spare-layout", default=None,
                        help="NAND spare layout preset (onfi, linear)")
    parser.add_argument("--page-size", type=int, default=2048)
    parser.add_argument("--spare-size", type=int, default=64)
    parser.add_argument("--no-filesystems", action="store_true",
                        help="skip filesystem probing (partitions only)")
    args = parser.parse_args()

    cleanup: Path | None = None
    path = args.path
    if path is None:
        fd, tmp_str = tempfile.mkstemp(prefix="deepview-auto-", suffix=".img")
        os.close(fd)
        tmp = Path(tmp_str)
        tmp.write_bytes(build_fat12_image())
        path = tmp
        cleanup = tmp
        print(f"(no path given — synthesised FAT12 image at {path})")

    geometry: NANDGeometry | None = None
    if args.ecc or args.ftl:
        # User wants NAND wrapping; synthesise a geometry from the image
        # size so auto_open has something reasonable to work with.
        size = path.stat().st_size
        # Assume a 1-to-1 data/spare layout; page-size granularity.
        total_page = args.page_size + args.spare_size
        total_pages = max(1, size // total_page)
        geometry = NANDGeometry(
            page_size=args.page_size,
            spare_size=args.spare_size,
            pages_per_block=64,
            blocks=max(1, total_pages // 64),
        )

    ctx = AnalysisContext.for_testing()
    result = auto_open(
        ctx,
        path,
        nand_geometry=geometry,
        ecc=args.ecc,
        ftl=args.ftl,
        spare_layout=args.spare_layout,
        open_filesystems=not args.no_filesystems,
    )

    print("AutoOpenResult")
    print(f"  raw_layer:         {result.raw_layer.metadata.name}")
    print(f"    range:           [0, {result.raw_layer.maximum_address}]")
    print(f"  transformed_layer: {result.transformed_layer.metadata.name}")
    print(f"    range:           [0, {result.transformed_layer.maximum_address}]")

    print(f"  partitions:        {len(result.partitions)}")
    for p in result.partitions:
        print(f"    [{p.index}] scheme={p.scheme} type={p.type_id} "
              f"start={p.start_offset:#x} size={p.size:#x} name={p.name!r}")

    print(f"  filesystems:       {len(result.filesystems)}")
    for idx, fs in result.filesystems.items():
        print(f"    [{idx}] fs={fs.fs_name} block_size={fs.block_size}")

    if result.notes:
        print("  notes:")
        for note in result.notes:
            print(f"    * {note}")
    else:
        print("  notes:             (none)")

    if cleanup is not None:
        try:
            cleanup.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
