"""SessionRecorder: subscribe to a TraceEventBus, persist into a store."""
from __future__ import annotations

import asyncio
import platform

from deepview.core.logging import get_logger
from deepview.replay.circular import CircularEventBuffer
from deepview.replay.store import SessionStore
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import EventSubscription, TraceEventBus

log = get_logger("replay.recorder")


class SessionRecorder:
    """Attach a session store to a live :class:`TraceEventBus`."""

    def __init__(
        self,
        bus: TraceEventBus,
        store: SessionStore,
        *,
        filter_text: str = "",
        circular: CircularEventBuffer | None = None,
    ) -> None:
        self._bus = bus
        self._store = store
        self._filter_text = filter_text
        self._circular = circular
        self._subscription: EventSubscription | None = None
        self._task: asyncio.Task | None = None
        self._running = False
        self._session_id: str | None = None

    @property
    def session_id(self) -> str | None:
        return self._session_id

    async def start(self) -> str:
        if self._running:
            assert self._session_id is not None
            return self._session_id
        self._session_id = self._store.open_session(
            hostname=platform.node(),
            kernel=platform.release(),
            filter_text=self._filter_text,
        )
        self._subscription = self._bus.subscribe()
        self._running = True
        self._task = asyncio.create_task(self._run())
        return self._session_id

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self._subscription is not None:
            self._bus.unsubscribe(self._subscription)
        dropped = self._subscription.dropped_count if self._subscription else 0
        self._store.close_session(dropped=dropped)
        self._subscription = None

    async def _run(self) -> None:
        assert self._subscription is not None
        while self._running:
            event = await self._subscription.get(timeout=0.5)
            if event is None:
                continue
            self._persist(event)

    def _persist(self, event: MonitorEvent) -> None:
        try:
            self._store.append_event(event)
        except Exception as e:  # noqa: BLE001
            log.warning("recorder_append_failed", error=str(e))
        if self._circular is not None:
            self._circular.append(event)

    def persist_snapshot(self, kind: str, payload: dict) -> None:
        self._store.append_snapshot(kind, payload)

    def flush_circular(self) -> int:
        """Dump the circular buffer into the store as a pre-event snapshot."""
        if self._circular is None:
            return 0
        events = self._circular.dump()
        if not events:
            return 0
        payload = {
            "events": [
                {
                    "ts_ns": e.timestamp_ns,
                    "wall_ns": e.wall_clock_ns,
                    "pid": e.process.pid if e.process else 0,
                    "comm": e.process.comm if e.process else "",
                    "syscall": e.syscall_name,
                    "args": e.args,
                }
                for e in events
            ]
        }
        self._store.append_snapshot("circular_buffer", payload)
        return len(events)
