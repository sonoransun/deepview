"""Subscribe sync and async handlers to core events.

Shows both :meth:`EventBus.subscribe` and :meth:`EventBus.subscribe_async`
against:

* :class:`OffloadJobCompletedEvent` — triggered by submitting a tiny
  PBKDF2 job through :attr:`context.offload`;
* :class:`ContainerUnlockedEvent` — triggered by publishing a fake
  event directly (no real container required).

Usage:
    python examples/10_event_bus_subscriber.py
"""
from __future__ import annotations

import argparse
import asyncio
import os

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    ContainerUnlockedEvent,
    OffloadJobCompletedEvent,
)
from deepview.offload.jobs import make_job


async def run() -> int:
    ctx = AnalysisContext.for_testing()
    bus = ctx.events

    # Counters shared between the handlers so we can assert + report.
    counts = {"sync_offload": 0, "async_container": 0, "async_offload": 0}

    # Sync handler.
    def sync_on_offload(ev: OffloadJobCompletedEvent) -> None:
        counts["sync_offload"] += 1
        status = "ok" if ev.ok else f"fail({ev.error})"
        print(f"[sync  handler] offload  job={ev.job_id[:8]} {status} "
              f"elapsed={ev.elapsed_s:.3f}s")

    # Async handler — awaited on the running loop.
    async def async_on_container(ev: ContainerUnlockedEvent) -> None:
        counts["async_container"] += 1
        # A trivial await so we prove the handler is really on the loop.
        await asyncio.sleep(0)
        print(f"[async handler] container format={ev.format} "
              f"produced={ev.produced_layer}")

    async def async_on_offload(ev: OffloadJobCompletedEvent) -> None:
        counts["async_offload"] += 1
        await asyncio.sleep(0)
        print(f"[async handler] offload  job={ev.job_id[:8]} backend={ev.backend}")

    bus.subscribe(OffloadJobCompletedEvent, sync_on_offload)
    bus.subscribe_async(OffloadJobCompletedEvent, async_on_offload)
    bus.subscribe_async(ContainerUnlockedEvent, async_on_container)

    # ------------------------------------------------------------------
    # Trigger a real offload to drive the sync path.
    # ------------------------------------------------------------------
    engine = ctx.offload
    job = make_job(
        kind="pbkdf2_sha256",
        payload={
            "password": b"demo",
            "salt": os.urandom(16),
            "iterations": 1000,
            "dklen": 32,
        },
        callable_ref="deepview.offload.kdf:pbkdf2_sha256",
    )
    fut = engine.submit(job)
    fut.await_result()

    # Publish completion *async* so the async handler fires too. The
    # sync completion callback on the engine already fired the sync
    # handler. We also publish a fake unlock event.
    fake_offload = OffloadJobCompletedEvent(
        job_id=job.job_id,
        ok=True,
        elapsed_s=0.001,
        backend="process",
        error=None,
    )
    fake_unlock = ContainerUnlockedEvent(
        format="luks",
        layer="synthetic",
        produced_layer="luks-decrypted",
        elapsed_s=0.42,
    )
    await bus.publish_async(fake_offload)
    await bus.publish_async(fake_unlock)

    # Give the loop one more tick so any pending async handlers settle.
    await asyncio.sleep(0)

    engine.shutdown(wait=True)

    print()
    print(f"Sync  OffloadJobCompleted  dispatched: {counts['sync_offload']}")
    print(f"Async OffloadJobCompleted  dispatched: {counts['async_offload']}")
    print(f"Async ContainerUnlocked    dispatched: {counts['async_container']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.parse_args()
    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
