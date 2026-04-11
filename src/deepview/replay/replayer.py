"""SessionReplayer: read events from a store and republish them.

The replayer's key invariant is that the private bus it publishes
onto is *indistinguishable from a live bus* — the same classifier,
renderer, and inspector code can subscribe to it without knowing
whether the events came from the kernel a second ago or a recorded
session yesterday.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from deepview.core.logging import get_logger
from deepview.replay.store import SessionReader
from deepview.tracing.filters import FilterExpr
from deepview.tracing.stream import TraceEventBus

log = get_logger("replay.replayer")


@dataclass
class ReplayStats:
    events_read: int = 0
    events_published: int = 0
    alerts_hit: int = 0


class SessionReplayer:
    """Republish stored events at configurable speed onto a private bus."""

    def __init__(
        self,
        reader: SessionReader,
        session_id: str,
        *,
        speed: float = 1.0,
        start_ns: int | None = None,
        end_ns: int | None = None,
        filter_expr: FilterExpr | None = None,
    ) -> None:
        self._reader = reader
        self._session_id = session_id
        self._speed = max(0.0, speed)
        self._start_ns = start_ns
        self._end_ns = end_ns
        self._filter_expr = filter_expr
        self._bus = TraceEventBus()
        self._stats = ReplayStats()

    @property
    def bus(self) -> TraceEventBus:
        return self._bus

    @property
    def stats(self) -> ReplayStats:
        return self._stats

    async def play(self, *, step: bool = False) -> ReplayStats:
        """Stream events until the session is exhausted.

        When *step* is true, no inter-event delay is applied regardless
        of the ``speed`` setting — useful for tests and for "replay
        into classifier" re-detection scenarios that do not need wall
        clock pacing.
        """
        prev_ts: int | None = None
        async for event in self._iter_events_async():
            self._stats.events_read += 1
            if self._filter_expr is not None and not self._filter_expr.evaluate(event):
                continue
            if not step and self._speed > 0 and prev_ts is not None:
                delta_ns = max(0, event.timestamp_ns - prev_ts)
                await asyncio.sleep(delta_ns / 1e9 / self._speed)
            prev_ts = event.timestamp_ns
            await self._bus.publish(event)
            self._stats.events_published += 1
        return self._stats

    async def _iter_events_async(self):
        """Generator wrapper so the sync SQLite iterator can be awaited."""
        iterator = self._reader.iter_events(
            session_id=self._session_id,
            start_ns=self._start_ns,
            end_ns=self._end_ns,
        )
        for event in iterator:
            yield event
            # Yield control back to the event loop so subscribers get a
            # chance to drain the bus even when step=True.
            await asyncio.sleep(0)
