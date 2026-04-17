# Recipe 05: Unlock LUKS with a passphrase

Unlock a LUKS1 or LUKS2 container with a user-supplied passphrase and use
the resulting `DecryptedVolumeLayer` like any other `DataLayer`.

!!! note "Extras required"
    `pip install -e ".[containers,offload]"`. The PBKDF2 or Argon2id
    derivation is dispatched onto `context.offload` so the caller
    thread never blocks on CPU work.

## The recipe

```python
import asyncio
import os
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.memory.formats.raw import RawMemoryLayer
from deepview.storage.containers.luks import LUKSUnlocker
from deepview.storage.containers.unlock import Passphrase

async def main() -> None:
    ctx = AnalysisContext()
    layer = RawMemoryLayer(Path("/evidence/luks.img"))
    ctx.layers.register("encrypted", layer)

    unlocker = LUKSUnlocker()

    # 1. Detect the header. Non-LUKS layers return None.
    header = unlocker.detect(layer, offset=0)
    if header is None:
        raise SystemExit("no LUKS header at offset 0")
    print(f"detected {header.format} cipher={header.cipher} "
          f"kdf={header.kdf} payload=0x{header.data_offset:x}")

    # 2. Derive the key through the offload engine + decrypt.
    source = Passphrase(passphrase=os.environ["LUKS_PASS"])
    decrypted = await unlocker.unlock(layer, header, source)

    # 3. The plaintext layer can be registered + read like any other.
    ctx.layers.register("plaintext", decrypted)
    print("magic =", decrypted.read(0, 16).hex())

asyncio.run(main())
```

## What happened

`LUKSUnlocker.detect` parses the `LUKS\xba\xbe` magic and returns a
`ContainerHeader` carrying the cipher name, KDF type, salt, iteration
count, and the data offset. `Passphrase.derive` lazily imports
`deepview.offload.kdf.pbkdf2_sha256` / `argon2id` and submits a job via
`context.offload.submit(...)` — the result bytes come back on
`OffloadFuture.await_result()`. No blocking sleep happens on the
asyncio loop thread.

The produced `DecryptedVolumeLayer` is a *read-only* view. Every
`read(offset, length)` decrypts the enclosing AES-XTS sectors on
demand; the ciphertext layer underneath is never modified. That is a
hard contract — see
[`architecture/containers.md`](../architecture/containers.md#read-only).

!!! danger "Passphrases on argv"
    Never pass passphrases on the command line or bake them into source.
    The CLI's `unlock luks --passphrase-env=NAME` reads from an
    environment variable specifically to avoid `ps`-visibility. Prefer
    the same pattern in scripts.

!!! tip "Already have the master key?"
    Substitute `MasterKey(key=bytes.fromhex("..."))` for `Passphrase(...)`
    to skip the KDF entirely — useful after
    [Recipe 06](06-extract-key-from-memory.md) has pulled an FVEK out of
    RAM.

## Equivalent CLI

```bash
deepview unlock luks luks.img \
    --passphrase-env=LUKS_PASS \
    --register-as plaintext
```

## Cross-links

- [Recipe 07](07-nested-decrypt-luks-in-veracrypt.md) — LUKS inside
  VeraCrypt.
- Architecture: [`architecture/containers.md`](../architecture/containers.md).
- Offload: [`architecture/offload.md`](../architecture/offload.md).
