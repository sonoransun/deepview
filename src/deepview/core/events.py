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


# ---------------------------------------------------------------------------
# Container unlock events
# ---------------------------------------------------------------------------


class ContainerUnlockStartedEvent(Event):
    """Emitted when an unlock attempt against an encrypted container begins."""

    def __init__(self, *, format: str, layer: str, key_source: str) -> None:
        self.format = format
        self.layer = layer
        self.key_source = key_source


class ContainerUnlockProgressEvent(Event):
    """Periodic progress for a multi-step unlock (KDF iterations, key tries)."""

    def __init__(self, *, format: str, stage: str, attempted: int, total: int) -> None:
        self.format = format
        self.stage = stage
        self.attempted = attempted
        self.total = total


class ContainerUnlockedEvent(Event):
    """Successful unlock; *produced_layer* is the registered name of the plaintext layer."""

    def __init__(
        self,
        *,
        format: str,
        layer: str,
        produced_layer: str,
        elapsed_s: float,
    ) -> None:
        self.format = format
        self.layer = layer
        self.produced_layer = produced_layer
        self.elapsed_s = elapsed_s


class ContainerUnlockFailedEvent(Event):
    """Unlock attempt exhausted all candidate keys / passphrases."""

    def __init__(self, *, format: str, layer: str, reason: str) -> None:
        self.format = format
        self.layer = layer
        self.reason = reason


# ---------------------------------------------------------------------------
# Remote acquisition events
# ---------------------------------------------------------------------------


class RemoteAcquisitionStartedEvent(Event):
    def __init__(self, *, endpoint: str, transport: str, output: str) -> None:
        self.endpoint = endpoint
        self.transport = transport
        self.output = output


class RemoteAcquisitionProgressEvent(Event):
    def __init__(
        self,
        *,
        endpoint: str,
        bytes_done: int,
        bytes_total: int,
        stage: str,
    ) -> None:
        self.endpoint = endpoint
        self.bytes_done = bytes_done
        self.bytes_total = bytes_total
        self.stage = stage


class RemoteAcquisitionCompletedEvent(Event):
    def __init__(
        self,
        *,
        endpoint: str,
        output: str,
        size_bytes: int,
        elapsed_s: float,
    ) -> None:
        self.endpoint = endpoint
        self.output = output
        self.size_bytes = size_bytes
        self.elapsed_s = elapsed_s


# ---------------------------------------------------------------------------
# Offload events
# ---------------------------------------------------------------------------


class OffloadJobSubmittedEvent(Event):
    def __init__(self, *, job_id: str, kind: str, backend: str, cost_hint: int) -> None:
        self.job_id = job_id
        self.kind = kind
        self.backend = backend
        self.cost_hint = cost_hint


class OffloadJobProgressEvent(Event):
    def __init__(self, *, job_id: str, fraction: float, message: str = "") -> None:
        self.job_id = job_id
        self.fraction = fraction
        self.message = message


class OffloadJobCompletedEvent(Event):
    def __init__(
        self,
        *,
        job_id: str,
        ok: bool,
        elapsed_s: float,
        backend: str,
        error: str | None = None,
    ) -> None:
        self.job_id = job_id
        self.ok = ok
        self.elapsed_s = elapsed_s
        self.backend = backend
        self.error = error


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
