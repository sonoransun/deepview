from __future__ import annotations
import asyncio
from collections import defaultdict
from typing import Any, Callable

class Event:
    """Base event class. Subclass for specific event types."""

class MemoryAcquiredEvent(Event):
    def __init__(self, path, dump_format, size_bytes=0):
        self.path = path
        self.dump_format = dump_format
        self.size_bytes = size_bytes

class SuspiciousPatternEvent(Event):
    def __init__(self, offset, rule_name, data=b""):
        self.offset = offset
        self.rule_name = rule_name
        self.data = data

class ProcessDetectedEvent(Event):
    def __init__(self, pid, ppid, comm, timestamp=0.0):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.timestamp = timestamp


class RootkitDetectedEvent(Event):
    def __init__(self, technique, description, severity="critical", evidence=None):
        self.technique = technique
        self.description = description
        self.severity = severity
        self.evidence = evidence or {}


class ArtifactRecoveredEvent(Event):
    def __init__(self, artifact_type, source, count=0, metadata=None):
        self.artifact_type = artifact_type
        self.source = source
        self.count = count
        self.metadata = metadata or {}


class MemoryDiffEvent(Event):
    def __init__(self, changed_pages, new_pages, removed_pages, change_rate=0.0):
        self.changed_pages = changed_pages
        self.new_pages = new_pages
        self.removed_pages = removed_pages
        self.change_rate = change_rate


class BaselineDeviationEvent(Event):
    def __init__(self, category, description, severity="warning", evidence=None):
        self.category = category
        self.description = description
        self.severity = severity
        self.evidence = evidence or {}

class EventBus:
    """Decoupled publish-subscribe event distribution."""

    def __init__(self):
        self._handlers: dict[type[Event], list[Callable]] = defaultdict(list)
        self._async_handlers: dict[type[Event], list[Callable]] = defaultdict(list)

    def subscribe(self, event_type: type[Event], handler: Callable) -> None:
        """Register a synchronous handler for an event type."""
        self._handlers[event_type].append(handler)

    def subscribe_async(self, event_type: type[Event], handler: Callable) -> None:
        """Register an async handler for an event type."""
        self._async_handlers[event_type].append(handler)

    def unsubscribe(self, event_type: type[Event], handler: Callable) -> None:
        """Remove a handler."""
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
        if handler in self._async_handlers[event_type]:
            self._async_handlers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        """Publish event to all synchronous handlers."""
        for handler in self._handlers.get(type(event), []):
            handler(event)
        # Also check parent classes
        for event_type, handlers in self._handlers.items():
            if event_type is not type(event) and isinstance(event, event_type):
                for handler in handlers:
                    handler(event)

    async def publish_async(self, event: Event) -> None:
        """Publish event to both sync and async handlers."""
        self.publish(event)
        for handler in self._async_handlers.get(type(event), []):
            await handler(event)
