# Recipe 03: Mount a filesystem on a disk image

Given a whole-disk image, enumerate partitions and probe each one for a
filesystem adapter without hard-coding types.

!!! note "Extras required"
    `pip install -e ".[storage]"` — native adapters for ext, NTFS, FAT, HFS+,
    APFS, btrfs, XFS, F2FS, ZFS ship in-tree. Install `[storage_tsk]` to fall
    back to The Sleuth Kit (`pytsk3`) for exotic filesystems.

## The recipe

```python
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.formats.raw import RawMemoryLayer
from deepview.storage.partition import PartitionLayer, parse_partitions

ctx = AnalysisContext()

# --- 1. Open the disk image as a byte layer ---------------------------
raw = RawMemoryLayer(Path("/evidence/disk.img"))
ctx.layers.register("disk", raw)

# --- 2. Parse the partition table (GPT then MBR) ----------------------
partitions = list(parse_partitions(raw))
for part in partitions:
    print(f"[{part.index}] type={part.type_guid} "
          f"offset=0x{part.start_offset:x} size={part.size} name={part.name!r}")

# --- 3. For each partition, try every registered filesystem ----------
for part in partitions:
    slice_ = PartitionLayer(raw, part.start_offset, part.size)
    try:
        fs = ctx.storage.open_filesystem(slice_)      # fs_type=None -> autodetect
    except Exception as exc:
        print(f"[{part.index}] no adapter matched: {exc}")
        continue
    print(f"[{part.index}] mounted as {fs.fs_name}, listing /:")
    for entry in fs.list("/", recursive=False):
        print("  ", entry.path, entry.size)
```

## What happened

`parse_partitions` prefers GPT (detected by the "EFI PART" magic) and
falls back to MBR. The returned `Partition` objects carry `type_guid`,
`start_offset`, `size`, and a human `name` where available.

`PartitionLayer` is a thin slice-view over the parent layer — no bytes
are copied. `StorageManager.open_filesystem(layer, fs_type=None)` iterates
every registered adapter and calls `cls.probe(layer, offset=0)` until one
returns `True`. Failures in any probe are swallowed (`probe` is
best-effort, not authoritative) and the next adapter is tried.

!!! tip "Force a specific adapter"
    Pass `fs_type="ntfs"` / `"ext"` / `"apfs"` etc. to skip auto-probing.
    Useful when the superblock is damaged and probe returns `False` but
    you know what the filesystem is.

!!! warning "Unknown partition types"
    If no adapter matches a partition, check the type GUID — LUKS
    (`CA7D7CCB-63ED-4C53-861C-1742536059CC`), BitLocker
    (`EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` marked by FVE header),
    and VeraCrypt containers all need
    [Recipe 05](05-unlock-luks-with-passphrase.md) /
    [Recipe 07](07-nested-decrypt-luks-in-veracrypt.md) before mounting.

## Equivalent CLI

```bash
deepview storage mount disk.img --partition 2 --register-as root-fs
deepview filesystem ls root-fs /
```

## Cross-links

- [Recipe 04](04-walk-deleted-files.md) — carve deleted files from the
  mounted filesystem.
- [Recipe 05](05-unlock-luks-with-passphrase.md) — unlock the LUKS
  partition before mounting.
- Architecture: [`architecture/storage.md`](../architecture/storage.md).
