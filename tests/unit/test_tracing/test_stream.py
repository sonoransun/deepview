"""Tests for trace event streaming infrastructure."""
from __future__ import annotations

import asyncio

import pytest

from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import EventSubscription, TraceEventBus


def _make_event(**kwargs) -> MonitorEvent:
    """Create a simple MonitorEvent for testing."""
    return MonitorEvent(**kwargs)


class TestTraceEventBusSync:
    """Synchronous tests for TraceEventBus."""

    def test_subscribe_returns_subscription(self):
        bus = TraceEventBus()
        sub = bus.subscribe()
        assert isinstance(sub, EventSubscription)

    def test_publish_delivers_to_subscriber(self):
        bus = TraceEventBus()
        sub = bus.subscribe()
        event = _make_event(syscall_name="open")

        bus.publish_sync(event)

        assert not sub.queue.empty()
        assert sub.queue.get_nowait() is event

    def test_publish_to_multiple_subscribers(self):
        bus = TraceEventBus()
        sub1 = bus.subscribe()
        sub2 = bus.subscribe()
        event = _make_event(syscall_name="read")

        bus.publish_sync(event)

        assert sub1.queue.get_nowait() is event
        assert sub2.queue.get_nowait() is event

    def test_unsubscribe_stops_delivery(self):
        bus = TraceEventBus()
        sub = bus.subscribe()
        bus.unsubscribe(sub)

        bus.publish_sync(_make_event(syscall_name="write"))

        assert sub.queue.empty()

    def test_dropped_count_on_full_queue(self):
        bus = TraceEventBus()
        sub = bus.subscribe(queue_size=1)

        # Publish 3 events into a queue that can hold only 1
        for i in range(3):
            bus.publish_sync(_make_event(syscall_name=f"call_{i}"))

        # First event should be in the queue, the other 2 dropped
        assert sub.dropped_count >= 2


@pytest.mark.asyncio
class TestTraceEventBusAsync:
    """Async tests for TraceEventBus."""

    async def test_async_publish(self):
        bus = TraceEventBus()
        sub = bus.subscribe()
        event = _make_event(syscall_name="execve")

        await bus.publish(event)

        assert not sub.queue.empty()
        assert sub.queue.get_nowait() is event

    async def test_subscription_get_with_timeout(self):
        bus = TraceEventBus()
        sub = bus.subscribe()

        # Empty queue with a short timeout should return None
        result = await sub.get(timeout=0.01)
        assert result is None
