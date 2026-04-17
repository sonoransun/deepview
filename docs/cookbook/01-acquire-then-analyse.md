# Recipe 01: Acquire then analyse

Acquire memory from the live host and run a Volatility plugin against the
resulting dump in a single Python session.

!!! note "Extras required"
    `pip install -e ".[memory]"` — pulls in `volatility3`. On Linux you also
    want `bcc` / LiME tooling on-path if you use the `lime` provider.

## The recipe

```python
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.manager import MemoryManager

ctx = AnalysisContext()
mgr = MemoryManager(ctx)

# --- 1. Acquire ---------------------------------------------------------
# method="auto" iterates every registered provider in platform order until
# one succeeds. On Linux that is AVML, then LiME, then LiveMemoryProvider.
out = Path("/tmp/mem.raw")
result = mgr.acquire(
    target=AcquisitionTarget(),
    output=out,
    method="auto",
    fmt=DumpFormat.RAW,
)
print(f"acquired {result.size_bytes / 1e9:.2f} GB in {result.duration_seconds:.1f}s")

# --- 2. Open as a DataLayer --------------------------------------------
layer = mgr.open_layer(out)
ctx.layers.register("live_mem", layer)

# --- 3. Run a Volatility plugin ----------------------------------------
engine = mgr.get_engine("auto")   # prefers volatility3 if installed
pslist = engine.run_plugin("windows.pslist.PsList", layer=layer)
for row in pslist:
    print(row["PID"], row["ImageFileName"])
```

## What happened

1. `MemoryManager.__init__` probes available providers lazily; the acquirer
   set is defined in [`memory/acquisition/`](https://github.com/your-org/deepseek/tree/main/src/deepview/memory/acquisition).
2. `acquire(method="auto")` falls through to the first provider that
   returns without exception — every provider validates its own
   preconditions (e.g. LiME requires the kernel module, AVML requires
   root). See [`reference/extras.md`](../reference/extras.md) for the
   platform matrix.
3. `open_layer` sniffs the magic bytes of the produced file and builds
   the matching `DataLayer` subclass (`RawMemoryLayer`, `LiMEMemoryLayer`,
   `ELFCoreLayer`, ...). Detection is purely content-driven; see
   [`memory/manager.py::detect_format`](https://github.com/your-org/deepseek/blob/main/src/deepview/memory/manager.py).
4. The Volatility engine is imported lazily; on a core install
   `get_engine("auto")` raises `AnalysisError` cleanly instead of
   producing an `ImportError` traceback.

!!! warning "Permissions"
    Live acquisition needs elevated privileges (root on Linux/macOS,
    Administrator on Windows). The CLI equivalent
    `deepview memory acquire` prints a clear refusal when run without
    them — programmatic callers see a provider-specific exception.

!!! tip "Skip acquisition entirely"
    When you already have a dump, jump straight to step 2 with
    `layer = mgr.open_layer(Path("/evidence/case42.lime"))`.

## Cross-links

- Architecture: [`architecture/storage.md`](../architecture/storage.md)
- CLI equivalent: `deepview memory acquire` — see [`reference/cli.md`](../reference/cli.md).
- Related recipe: [Recipe 03](03-mount-filesystem-on-disk-image.md) for disk images.
