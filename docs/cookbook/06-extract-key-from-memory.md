# Recipe 06: Extract a key from memory and unlock BitLocker

Scan a memory image for an AES/FVEK candidate, then feed it straight into
`BitLockerUnlocker` as a `MasterKey` — bypassing the KDF path entirely.

!!! note "Extras required"
    `pip install -e ".[memory,containers]"`. Unlocking BitLocker also needs
    `libbde`'s Python binding (`pybde`) — installed as part of
    `[containers]`.

!!! danger "Dual-use"
    Scanning memory for key material is a dual-use capability. Only do
    this against evidence you are authorized to examine. The CLI's
    `unlock auto --memory-dump` path mirrors this recipe and prints a
    consent banner — see [`cli/commands/unlock.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/cli/commands/unlock.py).

## The recipe

```python
import asyncio
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.detection.encryption_keys import EncryptionKeyScanner
from deepview.memory.formats.raw import RawMemoryLayer
from deepview.storage.containers.bitlocker import BitLockerUnlocker
from deepview.storage.containers.unlock import MasterKey

async def main() -> None:
    ctx = AnalysisContext()

    # --- 1. Load the memory dump and scan for AES schedules -----------
    mem = RawMemoryLayer(Path("/evidence/memory.raw"))
    data = mem.read(0, mem.maximum_address + 1, pad=True)
    scanner = EncryptionKeyScanner()
    findings = scanner.scan_aes_keys(data, offset=0)
    print(f"found {len(findings)} AES candidates")

    # --- 2. Load the BitLocker image and detect its header -----------
    disk = RawMemoryLayer(Path("/evidence/bitlocker.vhd"))
    unlocker = BitLockerUnlocker()
    header = unlocker.detect(disk)
    if header is None:
        raise SystemExit("no BitLocker header found")
    expected_len = header.kdf_params.get("dklen", 32)

    # --- 3. Try each candidate of the right length --------------------
    for cand in findings:
        if len(cand.key_data) != expected_len:
            continue
        try:
            decrypted = await unlocker.unlock(
                disk, header, MasterKey(key=bytes(cand.key_data))
            )
        except Exception:
            continue
        print(f"unlocked with candidate @0x{cand.offset:x} "
              f"({cand.key_type}, confidence={cand.confidence:.2f})")
        ctx.layers.register("plaintext", decrypted)
        return
    print("no candidate decrypted the volume")

asyncio.run(main())
```

## What happened

`EncryptionKeyScanner.scan_aes_keys` looks for AES key schedules — the
192-round expanded form of an AES-128 key is a distinctive pattern that
shows up verbatim in RAM for the full lifetime of the cipher
context. Candidates come back as `KeyFinding` records.

`MasterKey.derive(...)` is the bypass path: it returns `self.key`
without submitting a job to the offload engine. That means the unlock
attempt is a single AES-XTS decrypt of the header verification block —
cheap enough that iterating every candidate is viable.

!!! tip "Prefer `UnlockOrchestrator.auto_unlock()`"
    For a less manual workflow call
    `await ctx.unlocker.auto_unlock(layer, scan_keys=True)` — it scans
    every registered layer, collects candidates, and tries them against
    every registered unlocker (LUKS / BitLocker / FileVault2 /
    VeraCrypt). See the `unlock auto` CLI or
    [`architecture/containers.md`](../architecture/containers.md).

!!! warning "False positives"
    AES-schedule detection has false positives. The first candidate
    that decrypts the verification block wins; the rest are discarded.
    Don't rely on `scanner.scan_aes_keys` returning a single answer.

## Equivalent CLI

```bash
deepview unlock auto bitlocker.vhd --memory-dump memory.raw --confirm
```

## Cross-links

- [Recipe 05](05-unlock-luks-with-passphrase.md) — passphrase path
  (KDF-driven).
- Architecture: [`architecture/containers.md`](../architecture/containers.md).
- Detection: `deepview.detection.encryption_keys.EncryptionKeyScanner`.
