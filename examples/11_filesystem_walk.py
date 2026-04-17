"""Walk a filesystem recursively and emit a body-file style timeline.

Demonstrates the :class:`Filesystem` interface:

* auto-probe via :meth:`StorageManager.open_filesystem` (no explicit
  adapter name);
* walk the tree with ``recursive=True``;
* build a minimal Sleuthkit-style body file
  (``MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|btime``).

By default the script synthesises a FAT12 image with a few files so it
runs without any extras. Point ``--image`` at a real image to walk it.

Usage:
    python examples/11_filesystem_walk.py
    python examples/11_filesystem_walk.py --image disk.img --fs ext
    python examples/11_filesystem_walk.py --include-deleted
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.manager import MemoryManager

from examples._synthetic import BytesLayer, build_fat12_image


def emit_body_file(entry: object) -> str:
    """Format an :class:`FSEntry` as a body-file line."""
    from deepview.interfaces.filesystem import FSEntry
    assert isinstance(entry, FSEntry)
    return "|".join(str(x) for x in (
        "",                    # md5 (blank — we don't hash here)
        entry.path,
        entry.inode,
        oct(entry.mode),
        entry.uid,
        entry.gid,
        entry.size,
        int(entry.atime),
        int(entry.mtime),
        int(entry.ctime),
        int(entry.btime or 0),
    ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--image", type=Path, default=None,
                        help="path to a disk image (defaults to synthetic FAT12)")
    parser.add_argument("--fs", default=None,
                        help="filesystem adapter name (auto-probe if omitted)")
    parser.add_argument("--path", default="/",
                        help="starting directory inside the filesystem")
    parser.add_argument("--include-deleted", action="store_true",
                        help="include deleted directory entries")
    parser.add_argument("--body-file", action="store_true",
                        help="emit Sleuthkit body-file lines instead of table")
    args = parser.parse_args()

    ctx = AnalysisContext.for_testing()
    cleanup: Path | None = None

    if args.image is None:
        fd, tmp_str = tempfile.mkstemp(prefix="deepview-fs-", suffix=".img")
        os.close(fd)
        tmp = Path(tmp_str)
        tmp.write_bytes(build_fat12_image(files=[
            ("HELLO.TXT", b"hello from deepview\n"),
            ("README.MD", b"# Synthetic FAT12 image.\n"),
            ("DATA.BIN", b"\x00\x01\x02\x03" * 32),
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

    print(f"Filesystem: {fs.fs_name} block_size={fs.block_size}")
    print()

    entries = list(fs.list(args.path, recursive=True,
                           include_deleted=args.include_deleted))
    print(f"Entries under {args.path!r}: {len(entries)}")

    if args.body_file:
        for e in entries:
            print(emit_body_file(e))
    else:
        print(f"  {'Type':<6} {'Size':>10}  {'Path'}")
        print(f"  {'-'*6} {'-'*10}  {'-'*40}")
        for e in entries:
            kind = "DIR" if e.is_dir else ("DEL" if e.is_deleted else "FILE")
            print(f"  {kind:<6} {e.size:>10}  {e.path}")

    if cleanup is not None:
        try:
            cleanup.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
