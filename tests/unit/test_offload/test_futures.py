"""Unit tests for :mod:`deepview.offload.futures`."""
from __future__ import annotations

import asyncio
import sys
from concurrent.futures import Future, TimeoutError as FuturesTimeoutError
from pathlib import Path

import pytest

_TESTS_ROOT = Path(__file__).resolve().parents[2]
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))

from _factories import FakeEventBus  # noqa: E402
from deepview.core.events import OffloadJobProgressEvent  # noqa: E402
from deepview.offload.futures import (  # noqa: E402
    PROGRESS_QUEUE_MAXSIZE,
    OffloadFuture,
)
from deepview.offload.jobs import OffloadResult  # noqa: E402


def _make_result(job_id: str = "job-1", ok: bool = True) -> OffloadResult:
    return OffloadResult(
        job_id=job_id,
        ok=ok,
        output=b"x" if ok else None,
        error=None if ok else "boom",
        elapsed_s=0.0,
        backend="test",
    )


def test_cancel_before_completion_returns_true() -> None:
    fut: Future[OffloadResult] = Future()
    of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
    # A freshly-created stdlib Future in PENDING state can be cancelled.
    assert of.cancel() is True
    assert fut.cancelled() is True


def test_cancel_after_completion_returns_false() -> None:
    fut: Future[OffloadResult] = Future()
    of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
    fut.set_result(_make_result())
    assert of.cancel() is False


def test_done_transitions() -> None:
    fut: Future[OffloadResult] = Future()
    of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
    assert of.done() is False
    fut.set_result(_make_result())
    assert of.done() is True


def test_add_done_callback_fires_with_offload_future() -> None:
    fut: Future[OffloadResult] = Future()
    of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
    seen: list[object] = []

    def _cb(arg: OffloadFuture[object]) -> None:
        seen.append(arg)

    of.add_done_callback(_cb)
    fut.set_result(_make_result())

    assert len(seen) == 1
    assert seen[0] is of  # wrapper, not the stdlib future


def test_await_result_returns_wrapped_result() -> None:
    fut: Future[OffloadResult] = Future()
    of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
    expected = _make_result()
    fut.set_result(expected)

    got = of.await_result()
    assert got is expected
    assert got.ok is True


def test_await_result_timeout_on_pending() -> None:
    fut: Future[OffloadResult] = Future()
    of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
    with pytest.raises(FuturesTimeoutError):
        of.await_result(timeout=0.01)


def test_progress_events_yields_matching_and_ignores_others() -> None:
    """Events for other job_ids are ignored; matching events are yielded."""

    async def _run() -> list[float]:
        bus = FakeEventBus()
        fut: Future[OffloadResult] = Future()
        of: OffloadFuture[object] = OffloadFuture(fut, "job-1")
        seen: list[float] = []

        async def _consume() -> None:
            async for ev in of.progress_events(bus):
                seen.append(ev.fraction)

        task = asyncio.create_task(_consume())

        # Let the iterator subscribe.
        await asyncio.sleep(0)
        bus.publish(OffloadJobProgressEvent(job_id="job-1", fraction=0.25))
        bus.publish(OffloadJobProgressEvent(job_id="other", fraction=0.99))
        bus.publish(OffloadJobProgressEvent(job_id="job-1", fraction=0.50))

        # Yield so the queue drains into the consumer.
        for _ in range(5):
            await asyncio.sleep(0)

        fut.set_result(_make_result())
        await asyncio.wait_for(task, timeout=1.0)
        return seen

    result = asyncio.run(_run())
    assert result == [0.25, 0.50]


def test_progress_events_terminates_on_future_complete() -> None:
    async def _run() -> bool:
        bus = FakeEventBus()
        fut: Future[OffloadResult] = Future()
        of: OffloadFuture[object] = OffloadFuture(fut, "job-1")

        async def _consume() -> None:
            async for _ in of.progress_events(bus):
                pass

        task = asyncio.create_task(_consume())
        await asyncio.sleep(0)
        fut.set_result(_make_result())
        await asyncio.wait_for(task, timeout=1.0)
        return task.done()

    assert asyncio.run(_run()) is True


def test_progress_events_unsubscribes_on_break() -> None:
    """Iterator must unsubscribe from the bus when the consumer breaks out."""

    async def _run() -> int:
        bus = FakeEventBus()
        fut: Future[OffloadResult] = Future()
        of: OffloadFuture[object] = OffloadFuture(fut, "job-1")

        agen = of.progress_events(bus)

        async def _consume_one() -> None:
            async for _ in agen:
                break

        task = asyncio.create_task(_consume_one())
        await asyncio.sleep(0)
        bus.publish(OffloadJobProgressEvent(job_id="job-1", fraction=0.10))
        await asyncio.wait_for(task, timeout=1.0)
        # Explicitly close the async generator so the finally: unsubscribe
        # runs deterministically (break alone defers cleanup to GC).
        await agen.aclose()
        # Complete the future so any stray sentinel resolves cleanly.
        fut.set_result(_make_result())
        return len(bus._handlers.get(OffloadJobProgressEvent, []))

    handler_count = asyncio.run(_run())
    assert handler_count == 0


def test_progress_events_unsubscribes_on_normal_exit() -> None:
    """After the future completes, the iterator drains and unsubscribes."""

    async def _run() -> int:
        bus = FakeEventBus()
        fut: Future[OffloadResult] = Future()
        of: OffloadFuture[object] = OffloadFuture(fut, "job-1")

        async def _consume() -> None:
            async for _ in of.progress_events(bus):
                pass

        task = asyncio.create_task(_consume())
        await asyncio.sleep(0)
        fut.set_result(_make_result())
        await asyncio.wait_for(task, timeout=1.0)
        return len(bus._handlers.get(OffloadJobProgressEvent, []))

    assert asyncio.run(_run()) == 0


def test_progress_events_drops_on_overflow() -> None:
    """Publishing more than queue capacity increments dropped counter."""

    async def _run() -> tuple[int, int]:
        bus = FakeEventBus()
        fut: Future[OffloadResult] = Future()
        of: OffloadFuture[object] = OffloadFuture(fut, "job-1")

        collected: list[OffloadJobProgressEvent] = []
        subscribed = asyncio.Event()

        async def _consume() -> None:
            agen = of.progress_events(bus)
            # Prime: ensure subscription happens before publishes arrive.
            subscribed.set()
            async for ev in agen:
                collected.append(ev)

        task = asyncio.create_task(_consume())
        await subscribed.wait()
        # Let the iterator actually subscribe by running one loop turn.
        await asyncio.sleep(0)

        # Fire more than the queue can hold without yielding to the
        # consumer. We use call_soon to keep everything on the same loop.
        total = PROGRESS_QUEUE_MAXSIZE + 10
        for i in range(total):
            bus.publish(OffloadJobProgressEvent(job_id="job-1", fraction=i / total))

        # Now drain: yield control so the consumer can process.
        for _ in range(total * 2):
            await asyncio.sleep(0)

        fut.set_result(_make_result())
        await asyncio.wait_for(task, timeout=1.0)
        return len(collected), of.dropped_progress_events

    collected_count, dropped = asyncio.run(_run())
    # Capacity-bounded: consumer saw at most the queue size, and at
    # least one event overflowed.
    assert dropped >= 1
    assert collected_count <= PROGRESS_QUEUE_MAXSIZE
    # And the total accounted for cannot exceed the published count.
    assert collected_count + dropped <= PROGRESS_QUEUE_MAXSIZE + 10
