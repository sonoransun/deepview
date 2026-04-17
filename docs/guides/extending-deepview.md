# Extending Deep View

Deep View is designed to be extended without forking. Every subsystem
exposes a small abstract-base-class surface, and the relevant
registries auto-discover your implementation when it's importable.

This guide walks through two common extension scenarios:

1. **Adding a new filesystem adapter** — plug a new on-disk format
   into the `storage` subsystem.
2. **Adding a new container unlocker** — plug a new encrypted-volume
   format into the `unlock` orchestrator.

Both walkthroughs target a working, minimal example (~30 lines of
code each). Pattern, not polish, is the goal; once the scaffolding
works you can build up to a production adapter.

## Part A — adding a filesystem adapter

### The ABC

Every filesystem adapter subclasses `Filesystem` from
`src/deepview/interfaces/filesystem.py`:

```python
class Filesystem(ABC):
    fs_name: str = ""
    block_size: int = 0

    def __init__(self, layer: DataLayer, offset: int = 0) -> None: ...

    @classmethod
    @abstractmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool: ...

    @abstractmethod
    def list(self, path: str = "/", *, recursive: bool = False,
             include_deleted: bool = False) -> Iterator[FSEntry]: ...

    @abstractmethod
    def stat(self, path: str) -> FSEntry: ...

    @abstractmethod
    def open(self, path: str) -> DataLayer: ...

    @abstractmethod
    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes: ...
```

Implement five methods, wire one `register()` into
`storage/filesystems/registry.py::_ADAPTER_MODULES`, and you're live.

### Worked example — minimal Squashfs adapter

Squashfs is a read-only compressed filesystem used on routers, Live
CDs, and initramfs. A full adapter is a big job (LZ4/XZ/ZSTD
decompression, inode tables, directory indices); the stub below
covers probe + list-root + single-file read, which is enough to
integrate with Deep View's registry.

Create the file `src/deepview/storage/filesystems/squashfs.py`:

```python
"""Minimal Squashfs read-only adapter.

Probes for the Squashfs 4.0 magic (``hsqs`` at offset 0), reads the
superblock, decompresses the root directory table, and walks the
entries. Compression is stubbed to zlib only; add LZ4/XZ/ZSTD via
optional imports for production use.
"""
from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from typing import TYPE_CHECKING

from deepview.interfaces.filesystem import FSEntry, Filesystem

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer
    from deepview.storage.manager import StorageManager


SQUASHFS_MAGIC = b"hsqs"


class SquashfsFilesystem(Filesystem):
    """Probe-only + list-root skeleton for Squashfs 4.0."""

    fs_name = "squashfs"
    block_size = 4096

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)
        self._sb = self._read_superblock()

    @classmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        try:
            magic = layer.read(offset, 4)
        except Exception:
            return False
        return magic == SQUASHFS_MAGIC

    # ----- internals --------------------------------------------------

    def _read_superblock(self) -> dict[str, int]:
        raw = self.layer.read(self.offset, 96)
        # Squashfs 4.0 superblock layout — fields we care about only.
        inode_count, _mtime, blk_size, _frag_count = struct.unpack_from(
            "<IIII", raw, 4
        )
        return {"inode_count": inode_count, "block_size": blk_size}

    # ----- ABC implementations ---------------------------------------

    def list(self, path: str = "/", *, recursive: bool = False,
             include_deleted: bool = False) -> Iterator[FSEntry]:
        # Real impl: decompress the root directory table, walk dir
        # entries, yield FSEntry per inode. Stubbed here for brevity.
        yield FSEntry(
            path="/",
            inode=1,
            size=0,
            mode=0o040755,
            uid=0, gid=0,
            mtime=0.0, atime=0.0, ctime=0.0,
            is_dir=True,
        )

    def stat(self, path: str) -> FSEntry:
        if path == "/":
            return next(self.list("/"))
        raise FileNotFoundError(path)

    def open(self, path: str) -> DataLayer:
        raise NotImplementedError(
            "stub: squashfs file open requires block-table traversal"
        )

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        raise NotImplementedError(
            "stub: squashfs file read requires block decompression"
        )


def register(manager: StorageManager) -> None:
    """Called by ``storage.filesystems.registry.register_all``."""
    manager.register_filesystem("squashfs", SquashfsFilesystem)


__all__ = ["SquashfsFilesystem", "register"]
```

### Wire it into the registry

Edit `src/deepview/storage/filesystems/registry.py::_ADAPTER_MODULES`
and append your module name:

```python
_ADAPTER_MODULES: tuple[str, ...] = (
    "deepview.storage.filesystems.fat_native",
    "deepview.storage.filesystems.zfs",
    # ...
    "deepview.storage.filesystems.squashfs",   # <-- new
)
```

That's it. On the next `AnalysisContext.storage` access, the
`register_all()` helper imports your module and calls its
`register(manager)`. Auto-probe will try your adapter when
`filesystem ls --fs-type=auto` is invoked.

### Verify

```bash
deepview storage list
# Expect: 'squashfs' listed under "Filesystem adapters"

deepview filesystem ls --layer=some_sqfs_image --fs-type=squashfs
# Expect: '/' directory entry shown
```

### Notes for a production adapter

- **Use `_layer_io.LayerFileIO` when the native library is C**. It
  wraps a `DataLayer` in a file-like object compatible with
  `libfsapfs`, `libfsntfs`, etc. (See `fat_native.py` → pure-Python;
  `apfs.py` → LayerFileIO → `pyfsapfs`.)
- **Lazy-import the heavy dep inside `register()`** — Deep View's
  core install must stay importable without your adapter's native
  library.
- **Handle decompression inside the adapter**, not in a layer wrap.
  Squashfs blocks are variable-length and depend on the directory
  table index; stacking a `DecompressedDataLayer` would require
  per-file-specific offsets.

### Test it

Add a fixture under `tests/fixtures/storage/minimal.sqfs` (a real
squashfs image made with `mksquashfs`) and the usual pytest pattern:

```python
# tests/unit/test_storage/test_squashfs.py
from deepview.storage.filesystems.squashfs import SquashfsFilesystem
from deepview.memory.formats.raw import RawMemoryLayer


def test_squashfs_probes_a_valid_image(tmp_path):
    layer = RawMemoryLayer(tmp_path / "minimal.sqfs")
    assert SquashfsFilesystem.probe(layer) is True
```

---

## Part B — adding a container unlocker

### The ABC

Every container unlocker subclasses `Unlocker` from
`src/deepview/storage/containers/unlock.py`:

```python
class Unlocker(ABC):
    format_name: ClassVar[str] = ""

    @abstractmethod
    def detect(self, layer: DataLayer, offset: int = 0) -> ContainerHeader | None: ...

    @abstractmethod
    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> DecryptedVolumeLayer: ...
```

Unlike the filesystem registry, the unlocker orchestrator auto-
discovers adapters by looking for a **module-level `UNLOCKER`
attribute** (a class, not an instance) in a fixed list of module
paths.

### Reference — the LUKS adapter

Look at `src/deepview/storage/containers/luks.py` for a complete
worked example. It's ~400 lines but the shape is:

1. Parse the on-disk header in `detect()`, return a `ContainerHeader`
   or `None`. Detection is **synchronous** and must not allocate
   much — it's called against every layer during auto-detect.
2. `unlock()` is **async** because it calls `await source.derive(...)`
   which offloads the KDF.
3. Declare `UNLOCKER = LUKSUnlocker` at module top so the
   orchestrator's auto-discovery picks it up.

```python
# end of luks.py
class LUKSUnlocker(Unlocker):
    format_name = "LUKS"
    # ... detect() / unlock() ...

UNLOCKER = LUKSUnlocker
```

### Worked example — minimal "XorCrypt" unlocker

For pedagogy, here's a toy container that XORs every byte with a
single-byte key derived from SHA-256 of the passphrase. It's not
remotely secure — but it shows the whole unlock pipeline without
pulling in a 400-line cryptographic implementation.

Create `src/deepview/storage/containers/xorcrypt.py`:

```python
"""Toy 'XorCrypt' unlocker — teaching example only.

On-disk layout:
  offset 0..3    magic  = b"XORS"
  offset 4..11   length = payload length, little-endian uint64
  offset 12      payload bytes

Key = sha256(passphrase)[0:1] — a single byte. Decryption is a plain
XOR of every payload byte against that key.
"""
from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING, ClassVar

from deepview.interfaces.layer import DataLayer
from deepview.storage.containers.layer import DecryptedVolumeLayer
from deepview.storage.containers.unlock import (
    ContainerHeader,
    KeySource,
    MasterKey,
    Passphrase,
    Unlocker,
)

if TYPE_CHECKING:
    from deepview.offload.engine import OffloadEngine


MAGIC = b"XORS"
HEADER_SIZE = 12


class XorCryptUnlocker(Unlocker):
    format_name: ClassVar[str] = "XorCrypt"

    def detect(
        self, layer: DataLayer, offset: int = 0
    ) -> ContainerHeader | None:
        try:
            hdr = layer.read(offset, HEADER_SIZE)
        except Exception:
            return None
        if len(hdr) < HEADER_SIZE or hdr[:4] != MAGIC:
            return None
        (payload_len,) = struct.unpack_from("<Q", hdr, 4)
        return ContainerHeader(
            format="XorCrypt",
            cipher="xor-single-byte",
            sector_size=1,
            data_offset=offset + HEADER_SIZE,
            data_length=payload_len,
            kdf="pbkdf2_sha256",
            kdf_params={"salt": b"xorcrypt\x00", "iterations": 1, "dklen": 1},
        )

    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> DecryptedVolumeLayer:
        # Accept MasterKey (1 byte) or Passphrase (any length).
        if isinstance(source, MasterKey):
            key = source.key[:1] if source.key else b"\x00"
        elif isinstance(source, Passphrase):
            key = hashlib.sha256(source.passphrase.encode("utf-8")).digest()[:1]
        else:
            raise NotImplementedError(f"unsupported source {type(source).__name__}")

        # Read whole payload once — fine for a teaching example.
        ciphertext = layer.read(header.data_offset, header.data_length)
        plaintext = bytes(b ^ key[0] for b in ciphertext)

        from deepview.storage.containers.layer import (
            DecryptedVolumeLayer,
            InMemoryDecryptedBackend,
        )

        return DecryptedVolumeLayer(
            backend=InMemoryDecryptedBackend(plaintext),
            name="decrypted:xorcrypt",
        )


# Auto-discovery hook — the orchestrator imports this module and
# looks for ``UNLOCKER`` at module scope.
UNLOCKER = XorCryptUnlocker


__all__ = ["XorCryptUnlocker", "UNLOCKER"]
```

### Register it with the orchestrator

Edit `src/deepview/storage/containers/unlock.py::_AUTO_DISCOVER_MODULES`
to include your module:

```python
_AUTO_DISCOVER_MODULES: tuple[str, ...] = (
    "deepview.storage.containers.luks",
    "deepview.storage.containers.bitlocker",
    "deepview.storage.containers.filevault2",
    "deepview.storage.containers.veracrypt",
    "deepview.storage.containers.xorcrypt",  # <-- new
)
```

That's the only wiring. On the next `AnalysisContext.unlocker`
access, `UnlockOrchestrator._discover_builtin()` imports your module,
reads `UNLOCKER`, instantiates it, and registers.

### Verify

```python
from deepview.core.context import AnalysisContext
ctx = AnalysisContext.for_testing()
assert "XorCrypt" in ctx.unlocker.available_unlockers()
```

And via the CLI:

```bash
deepview unlock auto xorcrypt.bin --passphrase-list=/tmp/pws.txt
```

### Notes for a production unlocker

- **Header parsing must be robust**. `detect()` sees every arbitrary
  layer during auto-unlock; a malformed input must return `None`, not
  raise. Wrap the parse in `try/except Exception: return None`.
- **Offload the KDF via `Passphrase.derive()`**. Do not call
  `hashlib.pbkdf2_hmac()` inline — it blocks the async loop.
- **Support `MasterKey` shortcuts**. Even if your cipher has a
  complex KDF, accept a direct key for the memory-extraction path
  (see the LUKS adapter's fast branch when `isinstance(source,
  MasterKey)`).
- **`DecryptedVolumeLayer` is read-only by design**. The layer
  transparently decrypts on `.read(offset, length)` and forbids
  `.write()`. Don't try to write plaintext back to the container —
  that's out of scope for Deep View v1.

### Test it

The orchestrator's auto-discovery is deterministic, so a simple
smoke test is:

```python
from deepview.core.context import AnalysisContext


def test_xorcrypt_is_auto_discovered():
    ctx = AnalysisContext.for_testing()
    assert "XorCrypt" in ctx.unlocker.available_unlockers()
```

## Summary of both patterns

| Aspect | Filesystem adapter | Container unlocker |
|---|---|---|
| ABC location | `interfaces/filesystem.py::Filesystem` | `storage/containers/unlock.py::Unlocker` |
| Registry location | `storage/filesystems/registry.py` | `storage/containers/unlock.py` |
| Discovery mechanism | `register(manager)` module-level fn | `UNLOCKER` module-level class |
| Auto-registers on | `AnalysisContext.storage` first access | `AnalysisContext.unlocker` first access |
| Must be sync? | `probe` sync; rest sync too | `detect` sync; `unlock` **async** |
| Optional-dep handling | lazy-import inside `register()` | lazy-import inside `__init__` / `detect` |

## Common pitfalls

!!! warning "Module-level imports of optional deps break core installs"
    Always `from X import Y` **inside** `register()` or a method
    body. A hard module-level import means Deep View's core-only
    install can't even list your adapter's module.

!!! warning "Forgetting to add to the registry list"
    Your adapter class can be perfect, but if
    `_ADAPTER_MODULES` / `_AUTO_DISCOVER_MODULES` don't include your
    module path, nothing discovers it. The discovery is by module
    name, not by class inheritance — this is deliberate (import-time
    side effects are explicit).

!!! note "Third-party extensions via entry points"
    The plugin registry (see `src/deepview/plugins/registry.py`)
    supports `deepview.plugins` entry points. Filesystem / unlocker
    registries currently don't — but adding that is ~30 lines in
    each registry and is on the roadmap. Track the issue in the
    repo or pass `--plugin-path=<dir>` to auto-discover from a
    directory.

## What's next?

- [Storage walkthrough](storage-image-walkthrough.md) — see the
  `fat_native` adapter used end-to-end.
- [Unlock LUKS volume](unlock-luks-volume.md) — see the `LUKS`
  unlocker used end-to-end.
- [Architecture → Storage](../architecture/storage.md) and
  [→ Containers](../architecture/containers.md) — the complete
  subsystem diagrams.
- [Reference → Interfaces](../reference/interfaces.md) — ABC
  signatures for every extension point in Deep View.
