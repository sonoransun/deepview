"""In-memory circular buffer of the last N seconds of trace events.

The classifier hands us every event before it publishes onto the
classified bus. We keep the most recent window so that when a
critical rule fires we can dump the pre-event context into the
session store as a "lead-up" snapshot.
"""
from __future__ import annotations

import threading
import time
from collections import deque

from deepview.tracing.events import MonitorEvent


class CircularEventBuffer:
    """Bounded-time ring buffer of :class:`MonitorEvent`.

    The buffer drops events whose ``wall_clock_ns`` falls outside the
    configured window on every ``append`` call, so :meth:`dump` can
    return immediately without another pass.
    """

    def __init__(self, window_seconds: float = 60.0, max_events: int = 100_000) -> None:
        self._window_ns = int(window_seconds * 1_000_000_000)
        self._max_events = max_events
        self._events: deque[MonitorEvent] = deque()
        self._lock = threading.Lock()

    def append(self, event: MonitorEvent) -> None:
        now_ns = event.wall_clock_ns or time.time_ns()
        cutoff = now_ns - self._window_ns
        with self._lock:
            self._events.append(event)
            while self._events and (self._events[0].wall_clock_ns or 0) < cutoff:
                self._events.popleft()
            while len(self._events) > self._max_events:
                self._events.popleft()

    def dump(self) -> list[MonitorEvent]:
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
