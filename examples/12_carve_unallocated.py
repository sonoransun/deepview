"""Carve printable strings from unallocated filesystem regions.

Iterates :meth:`Filesystem.unallocated` and runs
:class:`deepview.scanning.string_carver.StringCarver` over each region's
bytes. For filesystems that don't expose unallocated regions yet (the
FAT12 pure-Python adapter for instance), we fall back to scanning the
raw backing layer so the demo produces output regardless.

Usage:
    python examples/12_carve_unallocated.py
    python examples/12_carve_unallocated.py --image disk.img --min-length 6
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.manager import MemoryManager
from deepview.scanning.string_carver import StringCarver

from examples._synthetic import BytesLayer, build_fat12_image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--image", type=Path, default=None,
                        help="path to a disk image (synthetic FAT12 if omitted)")
    parser.add_argument("--fs", default=None,
                        help="filesystem adapter name (auto-probe if omitted)")
    parser.add_argument("--min-length", type=int, default=5,
                        help="minimum string length (default 5)")
    parser.add_argument("--max-regions", type=int, default=64,
                        help="cap regions inspected")
    args = parser.parse_args()

    ctx = AnalysisContext.for_testing()
    cleanup: Path | None = None

    if args.image is None:
        fd, tmp_str = tempfile.mkstemp(prefix="deepview-carve-", suffix=".img")
        os.close(fd)
        tmp = Path(tmp_str)
        # Seed the image with a few files whose contents include some
        # "interesting" strings we expect to recover from slack space.
        tmp.write_bytes(build_fat12_image(files=[
            ("NOTES.TXT",
             b"SECRET_KEY=deepview-example-marker\n" * 8),
            ("README.MD",
             b"# Deep View carving demo\nreach out to root@example.com\n"),
        ]))
        layer = BytesLayer(tmp.read_bytes(), name="synthetic-fat")
        cleanup = tmp
        print(f"(synthetic FAT12 at {tmp})")
    else:
        manager = MemoryManager(ctx)
        layer = manager.open_layer(args.image)  # type: ignore[assignment]

    try:
        fs = ctx.storage.open_filesystem(layer, fs_type=args.fs)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not open filesystem: {exc}")
        return 2

    print(f"Filesystem: {fs.fs_name}")
    carver = StringCarver(min_length=args.min_length)

    unalloc = list(fs.unallocated())
    if unalloc:
        print(f"Unallocated regions exposed: {len(unalloc)}")
        for i, entry in enumerate(unalloc[: args.max_regions]):
            # Open the entry's file-layer and pull its bytes.
            try:
                region_layer = fs.open(entry.path)
            except Exception as exc:  # noqa: BLE001
                print(f"  [skip] {entry.path}: {exc}")
                continue
            data = region_layer.read(0, entry.size, pad=True)
            print(f"\n--- region[{i}] {entry.path} ({len(data)} bytes) ---")
            for s in carver.carve(data):
                print(f"  @{s.offset:#x} {s.encoding}: {s.value[:80]!r}")
    else:
        # FAT12 native adapter does not report unallocated entries, so we
        # carve the raw backing layer to still produce useful output.
        print("Adapter reports no unallocated regions.")
        print("Falling back to full-layer carve of the backing bytes...\n")
        size = layer.maximum_address + 1
        chunk = 64 * 1024
        seen = 0
        for pos in range(0, size, chunk):
            data = layer.read(pos, min(chunk, size - pos), pad=True)
            for s in carver.carve(data, base_offset=pos):
                print(f"  @{s.offset:#x} {s.encoding}: {s.value[:80]!r}")
                seen += 1
                if seen >= 40:
                    break
            if seen >= 40:
                break
        print(f"\nShown first {seen} strings.")

    if cleanup is not None:
        try:
            cleanup.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
