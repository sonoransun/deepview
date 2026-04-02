"""Event streaming infrastructure for tracing."""
from __future__ import annotations
import asyncio
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Callable
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr


class TraceEventBus:
    """Fan-out event distribution for trace events.

    Each subscriber gets its own asyncio.Queue. Slow consumers
    get events dropped (with counter) rather than blocking others.
    """

    def __init__(self):
        self._subscriptions: list[EventSubscription] = []
        self._lock = threading.Lock()

    def subscribe(self, queue_size: int = 8192, filter_expr: FilterExpr | None = None) -> EventSubscription:
        sub = EventSubscription(queue_size=queue_size, filter_expr=filter_expr)
        with self._lock:
            self._subscriptions.append(sub)
        return sub

    def unsubscribe(self, sub: EventSubscription) -> None:
        with self._lock:
            self._subscriptions = [s for s in self._subscriptions if s is not sub]

    async def publish(self, event: MonitorEvent) -> None:
        with self._lock:
            subs = list(self._subscriptions)
        for sub in subs:
            if sub.filter_expr and not sub.filter_expr.evaluate(event):
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                sub._dropped += 1

    def publish_sync(self, event: MonitorEvent) -> None:
        """Publish from a non-async context (e.g., polling thread)."""
        with self._lock:
            subs = list(self._subscriptions)
        for sub in subs:
            if sub.filter_expr and not sub.filter_expr.evaluate(event):
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                sub._dropped += 1


class EventSubscription:
    """An async-iterable subscription to the TraceEventBus."""

    def __init__(self, queue_size: int = 8192, filter_expr: FilterExpr | None = None):
        self.queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=queue_size)
        self.filter_expr = filter_expr
        self._dropped = 0

    @property
    def dropped_count(self) -> int:
        return self._dropped

    async def __aiter__(self) -> AsyncIterator[MonitorEvent]:
        return self

    async def __anext__(self) -> MonitorEvent:
        return await self.queue.get()

    async def get(self, timeout: float | None = None) -> MonitorEvent | None:
        try:
            if timeout is not None:
                return await asyncio.wait_for(self.queue.get(), timeout)
            return await self.queue.get()
        except asyncio.TimeoutError:
            return None
