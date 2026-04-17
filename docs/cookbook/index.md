# Cookbook

Short, focused Python-API recipes that compose Deep View's subsystems. Every
recipe is self-contained and ~50-150 lines — copy, adapt, run.

!!! tip "Prerequisites"
    Most recipes assume an editable install with the relevant extras, e.g.
    `pip install -e ".[memory,storage,offload_gpu,containers,remote_acquisition]"`.
    Each recipe flags the specific extras it needs in a callout near the top.

If you are new here, start with [`architecture/storage.md`](../architecture/storage.md)
and [`overview/data-layer-composition.md`](../overview/data-layer-composition.md)
— every recipe leans on the `DataLayer` composition contract.

## Recipes

| # | Recipe | What it shows |
|---|---|---|
| 01 | [Acquire then analyse](01-acquire-then-analyse.md) | `MemoryAcquisitionProvider` -> `MemoryManager.open_layer()` -> Volatility plugin. |
| 02 | [Stack NAND + ECC + FTL](02-stack-nand-ecc-ftl.md) | Compose `RawNANDLayer -> ECCDataLayer -> LinearizedFlashLayer` programmatically. |
| 03 | [Mount a filesystem on a disk image](03-mount-filesystem-on-disk-image.md) | Auto-detect partitions and open the right filesystem adapter. |
| 04 | [Walk deleted files](04-walk-deleted-files.md) | Iterate `Filesystem.unallocated()` and surface recoverable entries. |
| 05 | [Unlock LUKS with a passphrase](05-unlock-luks-with-passphrase.md) | `LUKSUnlocker().unlock(layer, header, Passphrase(...))`. |
| 06 | [Extract a key from memory and unlock BitLocker](06-extract-key-from-memory.md) | `EncryptionKeyScanner` -> `MasterKey` -> `BitLockerUnlocker`. |
| 07 | [Nested decrypt: LUKS inside VeraCrypt](07-nested-decrypt-luks-in-veracrypt.md) | Compose two unlockers by stacking the decrypted layers. |
| 08 | [Submit an offload job](08-submit-offload-job.md) | `context.offload.submit(make_job(...))` with custom callables. |
| 09 | [Stream trace events](09-stream-trace-events.md) | Subscribe to `EventClassifiedEvent` and print detections live. |
| 10 | [Record and replay a session](10-record-and-replay-session.md) | `SessionRecorder` + `SessionReplayer` round-trip. |
| 11 | [Build a `RemoteEndpoint` from env](11-build-remote-endpoint-config.md) | Safe credential indirection for `build_remote_provider()`. |
| 12 | [Write a custom `DataLayer`](12-write-a-custom-data-layer.md) | Subclass `DataLayer` for a compressed-page-table store. |

!!! info "Conventions"
    Every recipe uses `ctx = AnalysisContext()` or the `AnalysisContext.for_testing()`
    helper. Real CLI invocations build the context in `cli/app.py` and hand it
    off via `click.Context.obj["context"]` — see
    [`reference/cli.md`](../reference/cli.md).
