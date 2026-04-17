# Recipe 07: Nested decrypt — LUKS inside VeraCrypt

Show off the orthogonality of the unlock stack: the plaintext side of a
VeraCrypt unlock is *itself a `DataLayer`*, so you can feed it straight
into a second unlocker without serialization or re-imaging.

!!! note "Extras required"
    `pip install -e ".[containers,offload]"`.

## The recipe

```python
import asyncio
import os
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.formats.raw import RawMemoryLayer
from deepview.storage.containers.luks import LUKSUnlocker
from deepview.storage.containers.veracrypt import VeraCryptUnlocker
from deepview.storage.containers.unlock import Passphrase

async def main() -> None:
    ctx = AnalysisContext()
    raw = RawMemoryLayer(Path("/evidence/outer.hc"))

    # --- 1. Unlock the outer VeraCrypt container ----------------------
    vc = VeraCryptUnlocker()
    vc_header = vc.detect(raw)
    if vc_header is None:
        raise SystemExit("no VeraCrypt header")
    vc_layer = await vc.unlock(
        raw, vc_header,
        Passphrase(passphrase=os.environ["VC_PASS"]),
        try_hidden=False,
    )
    ctx.layers.register("vc_plain", vc_layer)

    # --- 2. Treat vc_layer as the source for LUKSUnlocker ------------
    luks = LUKSUnlocker()
    luks_header = luks.detect(vc_layer)       # probes the plaintext bytes
    if luks_header is None:
        raise SystemExit("no LUKS header inside the VeraCrypt volume")
    inner = await luks.unlock(
        vc_layer, luks_header,
        Passphrase(passphrase=os.environ["LUKS_PASS"]),
    )
    ctx.layers.register("inner_plain", inner)

    # --- 3. Read the deepest layer ------------------------------------
    print("inner magic:", inner.read(0, 16).hex())

asyncio.run(main())
```

## What happened

This recipe is the architecturally interesting one: *nothing special*
happens at layer-nesting time. The `vc_layer` returned by
`VeraCryptUnlocker.unlock(...)` implements the same `DataLayer`
contract as the original `RawMemoryLayer`. `LUKSUnlocker.detect(...)`
calls `vc_layer.read(0, N)` to sniff the header; `unlock(...)` calls
`vc_layer.read(data_offset, sector_size * K)` to decrypt ciphertext
blocks. The VeraCrypt layer decrypts its own blocks on demand in the
background — the LUKS layer has no idea anything unusual is going on.

```
LUKS plaintext
   └── reads -> LUKSUnlocker's DecryptedVolumeLayer
                   └── reads -> VeraCrypt plaintext (DecryptedVolumeLayer)
                                   └── reads -> RawMemoryLayer
                                                   └── mmap /evidence/outer.hc
```

!!! tip "Hidden volumes"
    Pass `try_hidden=True` on the outer unlock to probe for a hidden
    volume in the trailing region. The orchestrator sequence-diagram at
    [`architecture/containers.md`](../architecture/containers.md)
    walks this path explicitly.

!!! warning "Double KDF"
    Nested unlocks chain *two* KDF derivations. With default VeraCrypt
    iterations (500 000) and LUKS2 Argon2id (2 GiB / 4 threads) you will
    wait tens of seconds per attempt. Cache plaintext layers via
    `ctx.layers.register(...)` rather than re-unlocking.

## Equivalent CLI

No single CLI command chains two unlockers today. The equivalent
sequence is:

```bash
deepview unlock veracrypt outer.hc --passphrase-env=VC_PASS --register-as=vc_plain
# -- the second command consumes "vc_plain" via ctx.layers. Not yet wired
# -- in the CLI; use this recipe from Python.
```

## Cross-links

- [Recipe 05](05-unlock-luks-with-passphrase.md) — single LUKS unlock.
- Architecture: [`architecture/containers.md`](../architecture/containers.md).
