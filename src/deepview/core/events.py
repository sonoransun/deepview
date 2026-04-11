from __future__ import annotations
import threading
from collections import defaultdict
from typing import Callable

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


class NetworkPacketObservedEvent(Event):
    """Emitted for every packet the mangle engine sees."""

    def __init__(
        self,
        *,
        ts_ns: int,
        direction: str,
        ip_version: int,
        src: str,
        dst: str,
        proto: str,
        sport: int,
        dport: int,
        length: int,
    ) -> None:
        self.ts_ns = ts_ns
        self.direction = direction
        self.ip_version = ip_version
        self.src = src
        self.dst = dst
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.length = length


class NetworkPacketMangledEvent(Event):
    """Emitted for every matched mangle action.

    The dashboard's :class:`ManglePanel` subscribes to this class via
    the core :class:`EventBus` and uses it to drive its counters,
    top-rules view, and recent-actions table.
    """

    def __init__(
        self,
        *,
        ts_ns: int,
        rule_id: str,
        action: str,
        verdict: str,
        direction: str,
        description: str = "",
        remote: str = "",
        pid_guess: int = 0,
        comm_guess: str = "",
        before_bytes: int = 0,
        after_bytes: int = 0,
    ) -> None:
        self.ts_ns = ts_ns
        self.rule_id = rule_id
        self.action = action
        self.verdict = verdict
        self.direction = direction
        self.description = description
        self.remote = remote
        self.pid_guess = pid_guess
        self.comm_guess = comm_guess
        self.before_bytes = before_bytes
        self.after_bytes = after_bytes


class EventClassifiedEvent(Event):
    """Published by the classifier when a live event matches a rule."""

    def __init__(
        self,
        source_event,
        rule_id: str,
        severity: str,
        labels: dict[str, str] | None = None,
        attack_ids: list[str] | None = None,
        title: str = "",
    ):
        self.source_event = source_event
        self.rule_id = rule_id
        self.severity = severity
        self.labels = labels or {}
        self.attack_ids = attack_ids or []
        self.title = title

class EventBus:
    """Decoupled publish-subscribe event distribution."""

    def __init__(self):
        self._handlers: dict[type[Event], list[Callable]] = defaultdict(list)
        self._async_handlers: dict[type[Event], list[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, event_type: type[Event], handler: Callable) -> None:
        """Register a synchronous handler for an event type."""
        with self._lock:
            self._handlers[event_type].append(handler)

    def subscribe_async(self, event_type: type[Event], handler: Callable) -> None:
        """Register an async handler for an event type."""
        with self._lock:
            self._async_handlers[event_type].append(handler)

    def unsubscribe(self, event_type: type[Event], handler: Callable) -> None:
        """Remove a handler."""
        with self._lock:
            if handler in self._handlers[event_type]:
                self._handlers[event_type].remove(handler)
            if handler in self._async_handlers[event_type]:
                self._async_handlers[event_type].remove(handler)

    def publish(self, event: Event) -> None:
        """Publish event to all synchronous handlers."""
        with self._lock:
            exact = list(self._handlers.get(type(event), []))
            parent_handlers = []
            for event_type, handlers in self._handlers.items():
                if event_type is not type(event) and isinstance(event, event_type):
                    parent_handlers.extend(handlers)
        for handler in exact:
            handler(event)
        for handler in parent_handlers:
            handler(event)

    async def publish_async(self, event: Event) -> None:
        """Publish event to both sync and async handlers."""
        self.publish(event)
        with self._lock:
            async_handlers = list(self._async_handlers.get(type(event), []))
        for handler in async_handlers:
            await handler(event)
