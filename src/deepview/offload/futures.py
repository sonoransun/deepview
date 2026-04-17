"""Thin wrapper around :class:`concurrent.futures.Future` returned by
:meth:`deepview.offload.engine.OffloadEngine.submit`.

The wrapper exposes:

- the sync ``await_result`` / ``cancel`` / ``done`` / ``add_done_callback``
  surface so callers never have to touch the underlying stdlib future;
- an async ``progress_events(bus)`` iterator that yields every
  :class:`~deepview.core.events.OffloadJobProgressEvent` published for
  this ``job_id`` while the future is still pending. The iterator
  subscribes to *bus* via a *bounded* asyncio queue (matching the
  project-wide ``TraceEventBus`` drop-on-overflow contract) and cleans
  up the subscription (and a sentinel-stop task) when the future
  completes. Dropped events increment :attr:`dropped_progress_events`
  rather than back-pressuring the publisher.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from concurrent.futures import Future
from typing import TYPE_CHECKING, Generic, TypeVar

from deepview.core.events import OffloadJobProgressEvent
from deepview.offload.jobs import OffloadResult

if TYPE_CHECKING:
    from deepview.core.events import EventBus

T = TypeVar("T")

_logger = logging.getLogger(__name__)

PROGRESS_QUEUE_MAXSIZE = 128


class OffloadFuture(Generic[T]):
    """Typed wrapper around the stdlib future carrying an :class:`OffloadResult`."""

    __slots__ = ("_future", "_job_id", "dropped_progress_events")

    def __init__(self, future: Future[OffloadResult], job_id: str) -> None:
        self._future = future
        self._job_id = job_id
        self.dropped_progress_events = 0

    @property
    def job_id(self) -> str:
        return self._job_id

    def await_result(self, timeout: float | None = None) -> OffloadResult:
        """Block the calling thread until the job completes and return its result.

        If the underlying callable raised inside the worker, the backend
        wraps that exception into an ``OffloadResult(ok=False, error=...)``
        — so this method only raises for stdlib future failures
        (``TimeoutError``, ``CancelledError``) rather than for job
        failures.
        """
        return self._future.result(timeout=timeout)

    def cancel(self) -> bool:
        return self._future.cancel()

    def add_done_callback(self, cb: Callable[[OffloadFuture[T]], None]) -> None:
        def _wrapped(_stdlib: Future[OffloadResult]) -> None:
            cb(self)

        self._future.add_done_callback(_wrapped)

    def done(self) -> bool:
        return self._future.done()

    async def progress_events(
        self, bus: EventBus
    ) -> AsyncIterator[OffloadJobProgressEvent]:
        """Async-iterate over progress events for this job.

        Subscribes to *bus* with a bounded asyncio queue (``maxsize =
        PROGRESS_QUEUE_MAXSIZE``). Events whose ``job_id`` does not
        match this future are ignored. When the handler would overflow
        the queue, the incoming event is dropped and
        :attr:`dropped_progress_events` is incremented — matching the
        project-wide ``TraceEventBus`` drop-on-overflow contract.
        Sentinel delivery (future completion) is guaranteed: if the
        queue is full at completion time, the oldest queued event is
        discarded to make room for the sentinel, ensuring the iterator
        terminates.
        """
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[OffloadJobProgressEvent | None] = asyncio.Queue(
            maxsize=PROGRESS_QUEUE_MAXSIZE
        )

        def _handler(event: OffloadJobProgressEvent) -> None:
            if event.job_id != self._job_id:
                return

            def _put() -> None:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    self.dropped_progress_events += 1
                    _logger.debug(
                        "dropping progress event for job %s (queue full, dropped=%d)",
                        self._job_id,
                        self.dropped_progress_events,
                    )

            loop.call_soon_threadsafe(_put)

        def _on_done(_stdlib: Future[OffloadResult]) -> None:
            def _put_sentinel() -> None:
                while True:
                    try:
                        queue.put_nowait(None)
                        return
                    except asyncio.QueueFull:
                        try:
                            queue.get_nowait()
                        except asyncio.QueueEmpty:
                            return

            loop.call_soon_threadsafe(_put_sentinel)

        bus.subscribe(OffloadJobProgressEvent, _handler)
        self._future.add_done_callback(_on_done)
        try:
            while True:
                item = await queue.get()
                if item is None:
                    return
                yield item
        finally:
            bus.unsubscribe(OffloadJobProgressEvent, _handler)


__all__ = ["OffloadFuture"]
