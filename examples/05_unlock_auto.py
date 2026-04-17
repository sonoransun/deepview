"""Auto-detect + unlock every container :class:`UnlockOrchestrator` supports.

Wires the full orchestrator:

* optionally registers a memory dump as a layer so ``_collect_memory_keys``
  can scan it for AES master-key candidates;
* calls :meth:`context.unlocker.auto_unlock`, which walks every
  registered unlocker (LUKS, BitLocker, VeraCrypt, FileVault2 — whichever
  installed), tries master-key candidates, keyfiles, and passphrases in
  that order, and returns every successfully-unlocked
  :class:`DecryptedVolumeLayer`.

Usage:
    python examples/05_unlock_auto.py /path/to/container.img \\
        --memory-dump /path/to/memdump.raw \\
        --passphrase letmein --passphrase 'backup passphrase' \\
        --keyfile /path/to/keyfile --try-hidden

Requires the ``containers`` extra.
"""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    ContainerUnlockedEvent,
    ContainerUnlockFailedEvent,
    ContainerUnlockStartedEvent,
)
from deepview.memory.manager import MemoryManager


async def run(args: argparse.Namespace) -> int:
    ctx = AnalysisContext.for_testing()

    def on_started(ev: ContainerUnlockStartedEvent) -> None:
        print(f"[event] unlock start   format={ev.format} source={ev.key_source}")

    def on_ok(ev: ContainerUnlockedEvent) -> None:
        print(f"[event] unlock ok      format={ev.format} "
              f"produced={ev.produced_layer} elapsed={ev.elapsed_s:.2f}s")

    def on_fail(ev: ContainerUnlockFailedEvent) -> None:
        print(f"[event] unlock fail    format={ev.format} reason={ev.reason}")

    ctx.events.subscribe(ContainerUnlockStartedEvent, on_started)
    ctx.events.subscribe(ContainerUnlockedEvent, on_ok)
    ctx.events.subscribe(ContainerUnlockFailedEvent, on_fail)

    manager = MemoryManager(ctx)
    target_layer = manager.open_layer(args.path)
    ctx.layers.register("target", target_layer)

    if args.memory_dump is not None:
        mem_layer = manager.open_layer(args.memory_dump)
        ctx.layers.register("memdump", mem_layer)
        print(f"Registered memory dump {args.memory_dump} as "
              f"layer 'memdump' (for AES key harvesting)")

    unlocker = ctx.unlocker
    print(f"Available unlockers: {unlocker.available_unlockers()}")

    unlocked = await unlocker.auto_unlock(
        target_layer,
        passphrases=tuple(args.passphrase),
        keyfiles=tuple(Path(k) for k in args.keyfile),
        scan_keys=not args.no_scan_keys,
        try_hidden=args.try_hidden,
    )

    print()
    print(f"Unlocked layers: {len(unlocked)}")
    for i, layer in enumerate(unlocked):
        print(f"  [{i}] {layer.metadata.name} "
              f"size={layer.maximum_address + 1:,} bytes")
        head = layer.read(0, 64, pad=True)
        print(f"      first 64B: {head.hex()}")
    if not unlocked:
        print("  (none) — try adding more --passphrase candidates or a memory "
              "dump that holds the master key.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("path", type=Path, help="encrypted container image")
    parser.add_argument("--memory-dump", type=Path, default=None,
                        help="optional memory dump to scan for master-key material")
    parser.add_argument("--passphrase", action="append", default=[],
                        help="candidate passphrase (repeatable)")
    parser.add_argument("--keyfile", action="append", default=[],
                        help="candidate keyfile path (repeatable)")
    parser.add_argument("--no-scan-keys", action="store_true",
                        help="skip memory AES-key scanning")
    parser.add_argument("--try-hidden", action="store_true",
                        help="also probe for a VeraCrypt hidden volume")
    args = parser.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
