"""Tests for the event bus."""
import pytest
from deepview.core.events import (
    EventBus, Event, MemoryAcquiredEvent,
    SuspiciousPatternEvent, ProcessDetectedEvent,
)

class TestEventBus:
    def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []
        bus.subscribe(Event, lambda e: received.append(e))

        event = Event()
        bus.publish(event)
        assert len(received) == 1
        assert received[0] is event

    def test_typed_subscription(self):
        bus = EventBus()
        memory_events = []
        bus.subscribe(MemoryAcquiredEvent, lambda e: memory_events.append(e))

        bus.publish(Event())  # Should not trigger
        bus.publish(MemoryAcquiredEvent(path="/tmp/dump.raw", dump_format="raw"))

        assert len(memory_events) == 1
        assert memory_events[0].path == "/tmp/dump.raw"

    def test_unsubscribe(self):
        bus = EventBus()
        received = []
        handler = lambda e: received.append(e)
        bus.subscribe(Event, handler)
        bus.unsubscribe(Event, handler)
        bus.publish(Event())
        assert len(received) == 0

    def test_multiple_handlers(self):
        bus = EventBus()
        r1, r2 = [], []
        bus.subscribe(Event, lambda e: r1.append(e))
        bus.subscribe(Event, lambda e: r2.append(e))
        bus.publish(Event())
        assert len(r1) == 1
        assert len(r2) == 1

    def test_suspicious_pattern_event(self):
        event = SuspiciousPatternEvent(offset=0x1000, rule_name="malware_sig", data=b"\x90\x90")
        assert event.offset == 0x1000
        assert event.rule_name == "malware_sig"

    def test_process_detected_event(self):
        event = ProcessDetectedEvent(pid=1234, ppid=1, comm="evil")
        assert event.pid == 1234
