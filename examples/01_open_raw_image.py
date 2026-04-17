"""Open any memory image as a :class:`DataLayer` and hex-dump the head.

Demonstrates the simplest possible use of the Deep View storage stack:
``MemoryManager.open_layer()`` auto-detects the file format (raw, LiME,
ELF core, crash dump, hibernation, VMware .vmem, VirtualBox .sav, ...)
and returns a byte-addressable :class:`DataLayer`.

Usage:
    python examples/01_open_raw_image.py /path/to/memory.raw
    python examples/01_open_raw_image.py /path/to/image.lime --offset 4096 --length 128

With no ``--path`` argument the script synthesises a 1 MiB buffer on the
fly (written to a temp file) so the example is self-contained.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.manager import MemoryManager


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base + i:08x}  {hx:<{width * 3}}  {asc}")
    return "\n".join(lines)


def _make_demo_image() -> Path:
    """Create a small throwaway image file for the default demo."""
    fd, path = tempfile.mkstemp(prefix="deepview-demo-", suffix=".raw")
    os.close(fd)
    p = Path(path)
    payload = b"DEEPVIEW DEMO IMAGE\n" * 100
    p.write_bytes(payload + b"\x00" * (4096 - len(payload)))
    return p


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("path", nargs="?", type=Path,
                        help="path to a memory dump (raw / LiME / ELF core / etc.)")
    parser.add_argument("--offset", type=int, default=0, help="starting byte offset")
    parser.add_argument("--length", type=int, default=256, help="bytes to hex-dump")
    args = parser.parse_args()

    cleanup: Path | None = None
    path = args.path
    if path is None:
        path = _make_demo_image()
        cleanup = path
        print(f"(no path supplied — generated demo image at {path})")

    ctx = AnalysisContext.for_testing()
    manager = MemoryManager(ctx)
    fmt = manager.detect_format(path)
    print(f"Path:      {path}")
    print(f"Format:    {fmt.value}")
    print(f"Size:      {path.stat().st_size:,} bytes")

    layer = manager.open_layer(path, fmt=fmt)
    meta = layer.metadata
    print(f"Layer:     {meta.name}")
    print(f"Range:     [{layer.minimum_address}, {layer.maximum_address}]")
    print()

    if args.length > 0:
        data = layer.read(args.offset, args.length, pad=True)
        print(f"First {len(data)} bytes from offset {args.offset:#x}:")
        print(hexdump(data, base=args.offset))

    if cleanup is not None:
        try:
            cleanup.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
