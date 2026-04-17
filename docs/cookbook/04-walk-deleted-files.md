# Recipe 04: Walk deleted files

Iterate every recoverable entry a filesystem adapter can surface via its
`unallocated()` generator, carve matching bytes, and write them out.

!!! note "Extras required"
    `pip install -e ".[storage]"`. The unallocated-walker is implemented
    per-adapter — ext* and NTFS are the most complete; APFS/F2FS carve
    journal-referenced inodes only.

## The recipe

```python
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.formats.raw import RawMemoryLayer

ctx = AnalysisContext()

raw = RawMemoryLayer(Path("/evidence/disk.img"))
fs = ctx.storage.open_filesystem(raw)      # autodetect
print(f"fs={fs.fs_name}")

out_dir = Path("/tmp/carved")
out_dir.mkdir(parents=True, exist_ok=True)

recovered = 0
for entry in fs.unallocated():
    if entry.is_dir:
        continue
    if entry.size <= 0 or entry.size > 100 * 1024 * 1024:
        continue     # skip zero-byte tombstones and absurd sizes
    try:
        data = fs.read(entry.path, offset=0, length=entry.size)
    except Exception as exc:
        print(f"skip {entry.path!r}: {exc}")
        continue

    # Name on disk: last path component + inode to de-dupe collisions.
    name = f"{entry.inode}_{entry.path.rsplit('/', 1)[-1] or 'unnamed'}"
    (out_dir / name).write_bytes(data)
    recovered += 1

print(f"recovered {recovered} files into {out_dir}")
```

## What happened

`Filesystem.unallocated()` yields `FSEntry` records with
`is_deleted=True`. The default `Filesystem.unallocated()` returns an
empty iterator — adapters that support recovery override it. For ext4
the generator walks the journal for free-but-referenced inodes; for NTFS
it walks the MFT for entries whose in-use bit is clear. The
`FSEntry.extra` mapping may carry adapter-specific fields (e.g.
`"fragmented": True`, `"runs": [(lba, len), ...]`).

!!! tip "Filter before reading"
    Reading the bytes of every candidate is expensive and often
    pointless. Filter by `entry.size`, `entry.mtime`, or the extension
    in `entry.path` before committing to a `read()`.

!!! warning "Carve fidelity"
    Deleted-file recovery is best-effort. Block-reuse overwrites data
    long before the inode is reallocated. If the recovered bytes look
    wrong, cross-check the inode's run list against the bitmap — adapters
    expose a `diagnose()` hook under `FSEntry.extra` where possible.

## Equivalent CLI

```bash
deepview filesystem unallocated disk.img --min-size 4096 --output-dir /tmp/carved
```

## Cross-links

- [Recipe 03](03-mount-filesystem-on-disk-image.md) — how `fs` got mounted.
- [Recipe 12](12-write-a-custom-data-layer.md) — wrap the carved files
  in a layer for further scanning.
- Interface: [`reference/interfaces.md#filesystem`](../reference/interfaces.md).
