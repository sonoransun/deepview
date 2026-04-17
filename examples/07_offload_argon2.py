"""Offload Argon2id jobs to the process pool.

Same shape as ``06_offload_pbkdf2.py`` but runs the memory-hard
Argon2id KDF. Requires the ``containers`` extra (``argon2-cffi``);
the script prints a friendly install hint and exits cleanly if
unavailable.

Usage:
    python examples/07_offload_argon2.py --jobs 4 --time-cost 2 \\
        --memory-cost 65536 --parallelism 2
"""
from __future__ import annotations

import argparse
import os
import time

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    OffloadJobCompletedEvent,
    OffloadJobSubmittedEvent,
)
from deepview.offload.jobs import make_job


def _argon2_available() -> bool:
    try:
        import argon2  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--time-cost", type=int, default=2)
    parser.add_argument("--memory-cost", type=int, default=64 * 1024,
                        help="memory cost in KiB (default 65536 = 64 MiB)")
    parser.add_argument("--parallelism", type=int, default=2)
    parser.add_argument("--dklen", type=int, default=32)
    parser.add_argument("--backend", default="process")
    args = parser.parse_args()

    if not _argon2_available():
        print("argon2-cffi is not installed.")
        print("Install the containers extra: pip install -e '.[containers]'")
        return 2

    ctx = AnalysisContext.for_testing()
    completed = 0

    def on_submit(ev: OffloadJobSubmittedEvent) -> None:
        print(f"[submit]   job={ev.job_id[:8]} backend={ev.backend} kind={ev.kind}")

    def on_complete(ev: OffloadJobCompletedEvent) -> None:
        nonlocal completed
        if ev.ok:
            completed += 1
            print(f"[complete] job={ev.job_id[:8]} elapsed={ev.elapsed_s:.3f}s")
        else:
            print(f"[complete] job={ev.job_id[:8]} FAIL {ev.error}")

    ctx.events.subscribe(OffloadJobSubmittedEvent, on_submit)
    ctx.events.subscribe(OffloadJobCompletedEvent, on_complete)

    engine = ctx.offload
    print(f"Engine backends: {sorted(engine.backends())}")

    futures = []
    start = time.monotonic()
    for i in range(args.jobs):
        job = make_job(
            kind="argon2id",
            payload={
                "password": f"argon-{i}".encode(),
                "salt": os.urandom(16),
                "time_cost": args.time_cost,
                "memory_cost": args.memory_cost,
                "parallelism": args.parallelism,
                "dklen": args.dklen,
            },
            callable_ref="deepview.offload.kdf:argon2id",
            cost_hint=3,
        )
        futures.append(engine.submit(job, backend=args.backend))

    results = [f.await_result() for f in futures]
    elapsed = time.monotonic() - start

    print()
    print(f"Wall-clock elapsed:  {elapsed:.3f}s across {len(futures)} jobs")
    print(f"Completed ok:        {completed}/{len(futures)}")
    for r in results:
        out = r.output if isinstance(r.output, (bytes, bytearray)) else b""
        print(f"  job={r.job_id[:8]} ok={r.ok} elapsed={r.elapsed_s:.3f}s "
              f"digest={bytes(out).hex()[:32]}...")

    engine.shutdown(wait=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
