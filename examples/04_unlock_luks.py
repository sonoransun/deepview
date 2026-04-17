"""Unlock a LUKS volume with a passphrase and read the first plaintext sector.

Demonstrates the offload-driven KDF path for container unlock:

1. Subscribes a handler to :class:`ContainerUnlockStartedEvent` /
   :class:`ContainerUnlockProgressEvent` / :class:`ContainerUnlockedEvent`
   so you can see each stage fly by.
2. Instantiates :class:`LUKSUnlocker` directly, detects the header,
   then calls ``unlock()`` with a :class:`Passphrase` key source. The
   KDF (PBKDF2 or Argon2id) is automatically routed through
   ``context.offload`` via the process-pool backend.
3. Reads the first 512 bytes of the returned
   :class:`DecryptedVolumeLayer` and hex-dumps them.

Requires the ``containers`` extra (``cryptography`` and optionally
``argon2-cffi`` for LUKS2 Argon2id keyslots).

Usage:
    export DEEPVIEW_LUKS_PASSPHRASE='your passphrase'
    python examples/04_unlock_luks.py /path/to/luks.img \\
                                      --passphrase-env DEEPVIEW_LUKS_PASSPHRASE
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    ContainerUnlockedEvent,
    ContainerUnlockFailedEvent,
    ContainerUnlockProgressEvent,
    ContainerUnlockStartedEvent,
)
from deepview.memory.manager import MemoryManager


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base + i:08x}  {hx:<{width * 3}}  {asc}")
    return "\n".join(lines)


async def run(path: Path, passphrase: str) -> int:
    try:
        from deepview.storage.containers.luks import LUKSUnlocker
        from deepview.storage.containers.unlock import Passphrase
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to import LUKS adapter: {exc}")
        print("Install the containers extra: pip install -e '.[containers]'")
        return 2

    ctx = AnalysisContext.for_testing()

    # --- subscribe to unlock events ---
    def on_started(ev: ContainerUnlockStartedEvent) -> None:
        print(f"[event] unlock started   format={ev.format} source={ev.key_source}")

    def on_progress(ev: ContainerUnlockProgressEvent) -> None:
        print(f"[event] unlock progress  stage={ev.stage} "
              f"attempted={ev.attempted}/{ev.total}")

    def on_ok(ev: ContainerUnlockedEvent) -> None:
        print(f"[event] unlocked         produced={ev.produced_layer} "
              f"elapsed={ev.elapsed_s:.3f}s")

    def on_fail(ev: ContainerUnlockFailedEvent) -> None:
        print(f"[event] unlock failed    reason={ev.reason}")

    bus = ctx.events
    bus.subscribe(ContainerUnlockStartedEvent, on_started)
    bus.subscribe(ContainerUnlockProgressEvent, on_progress)
    bus.subscribe(ContainerUnlockedEvent, on_ok)
    bus.subscribe(ContainerUnlockFailedEvent, on_fail)

    manager = MemoryManager(ctx)
    layer = manager.open_layer(path)

    unlocker = LUKSUnlocker()
    header = unlocker.detect(layer)
    if header is None:
        print(f"{path}: not a LUKS volume")
        return 3

    print(f"Detected LUKS: format={header.format} cipher={header.cipher} "
          f"kdf={header.kdf} sector_size={header.sector_size}")

    source = Passphrase(passphrase=passphrase)
    try:
        plaintext_layer = await unlocker.unlock(layer, header, source)
    except Exception as exc:  # noqa: BLE001
        print(f"unlock failed: {exc}")
        return 4

    print()
    print(f"Plaintext layer: {plaintext_layer.metadata.name}")
    print(f"Plaintext size:  {plaintext_layer.maximum_address + 1:,} bytes")
    first = plaintext_layer.read(0, 512, pad=True)
    print("\nFirst 512 bytes of plaintext:")
    print(hexdump(first[:256]))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("path", type=Path, help="path to a LUKS container image")
    parser.add_argument("--passphrase-env", default="DEEPVIEW_LUKS_PASSPHRASE",
                        help="env var holding the passphrase (default "
                             "DEEPVIEW_LUKS_PASSPHRASE)")
    args = parser.parse_args()

    passphrase = os.environ.get(args.passphrase_env, "")
    if not passphrase:
        print(f"No passphrase in ${args.passphrase_env} — set it and retry.",
              file=sys.stderr)
        return 2
    return asyncio.run(run(args.path, passphrase))


if __name__ == "__main__":
    raise SystemExit(main())
