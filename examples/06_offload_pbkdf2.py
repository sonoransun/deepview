"""Submit a handful of PBKDF2 jobs to the process-pool offload backend.

Demonstrates:

* building :class:`OffloadJob` via :func:`deepview.offload.jobs.make_job`
  with a ``callable_ref`` pointing at
  :func:`deepview.offload.kdf.pbkdf2_sha256`;
* firing them into :meth:`context.offload.submit` on the default
  process-pool backend;
* awaiting every :class:`OffloadFuture` and printing a timing summary;
* subscribing to :class:`OffloadJobSubmittedEvent` +
  :class:`OffloadJobCompletedEvent` on the event bus so every job's
  lifecycle is surfaced.

Usage:
    python examples/06_offload_pbkdf2.py --jobs 8 --iterations 100000
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--jobs", type=int, default=8, help="number of jobs to submit")
    parser.add_argument("--iterations", type=int, default=50_000,
                        help="PBKDF2 iteration count per job")
    parser.add_argument("--backend", default="process",
                        help="offload backend name (default: process)")
    args = parser.parse_args()

    ctx = AnalysisContext.for_testing()

    # Counters, updated in-place by the event handlers.
    submitted = 0
    completed = 0
    failed = 0

    def on_submit(ev: OffloadJobSubmittedEvent) -> None:
        nonlocal submitted
        submitted += 1
        print(f"[submit]   job={ev.job_id[:8]} kind={ev.kind} backend={ev.backend}")

    def on_complete(ev: OffloadJobCompletedEvent) -> None:
        nonlocal completed, failed
        if ev.ok:
            completed += 1
            print(f"[complete] job={ev.job_id[:8]} ok "
                  f"elapsed={ev.elapsed_s:.3f}s backend={ev.backend}")
        else:
            failed += 1
            print(f"[complete] job={ev.job_id[:8]} FAIL error={ev.error}")

    ctx.events.subscribe(OffloadJobSubmittedEvent, on_submit)
    ctx.events.subscribe(OffloadJobCompletedEvent, on_complete)

    engine = ctx.offload
    print(f"Engine backends: {sorted(engine.backends())}")

    # Build + submit jobs.
    futures = []
    start = time.monotonic()
    for i in range(args.jobs):
        job = make_job(
            kind="pbkdf2_sha256",
            payload={
                "password": f"password-{i}".encode(),
                "salt": os.urandom(16),
                "iterations": args.iterations,
                "dklen": 32,
            },
            callable_ref="deepview.offload.kdf:pbkdf2_sha256",
            cost_hint=1,
        )
        fut = engine.submit(job, backend=args.backend)
        futures.append(fut)

    # Await results.
    results = []
    for fut in futures:
        res = fut.await_result()
        results.append(res)

    elapsed = time.monotonic() - start
    print()
    print(f"Wall-clock elapsed:  {elapsed:.3f}s across {len(futures)} jobs")
    print(f"Submitted events:    {submitted}")
    print(f"Completed events:    {completed}  failed: {failed}")
    print()
    print("Per-job results:")
    for res in results:
        out = res.output
        digest = out.hex() if isinstance(out, (bytes, bytearray)) else repr(out)
        status = "ok" if res.ok else f"FAIL ({res.error})"
        print(f"  job={res.job_id[:8]} {status:<6} backend={res.backend} "
              f"elapsed={res.elapsed_s:.3f}s digest={digest[:32]}...")

    engine.shutdown(wait=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
