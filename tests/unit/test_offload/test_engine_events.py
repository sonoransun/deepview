"""Verify engine publishes submit + complete events in order."""
from __future__ import annotations

import threading

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    OffloadJobCompletedEvent,
    OffloadJobSubmittedEvent,
)
from deepview.offload.jobs import make_job


def test_engine_publishes_submit_then_complete() -> None:
    context = AnalysisContext.for_testing()
    try:
        events: list[object] = []
        completed = threading.Event()

        def on_submit(ev: OffloadJobSubmittedEvent) -> None:
            events.append(ev)

        def on_complete(ev: OffloadJobCompletedEvent) -> None:
            events.append(ev)
            completed.set()

        context.events.subscribe(OffloadJobSubmittedEvent, on_submit)
        context.events.subscribe(OffloadJobCompletedEvent, on_complete)

        job = make_job(
            "sha512",
            {"data": b"hello", "iterations": 10},
            callable_ref="deepview.offload.kdf:sha512_iter",
        )
        future = context.offload.submit(job, backend="thread")
        result = future.await_result(timeout=10)
        assert result.ok, result.error

        # The completion event is fired from a done-callback running on
        # the pool's worker thread; give it up to 5s to propagate.
        assert completed.wait(timeout=5)

        # Order: submit event strictly before the completion event.
        assert len(events) == 2
        assert isinstance(events[0], OffloadJobSubmittedEvent)
        assert isinstance(events[1], OffloadJobCompletedEvent)
        assert events[0].job_id == job.job_id  # type: ignore[attr-defined]
        assert events[1].job_id == job.job_id  # type: ignore[attr-defined]
        assert events[0].backend == "thread"  # type: ignore[attr-defined]
        assert events[1].backend == "thread"  # type: ignore[attr-defined]
        assert events[1].ok is True  # type: ignore[attr-defined]
    finally:
        context.offload.shutdown(wait=True)
