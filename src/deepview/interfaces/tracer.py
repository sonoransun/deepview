from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field

from deepview.core.types import (
    EventCategory,
    EventSeverity,
    EventSource,
    ProbeType,
    ProcessContext,
)


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------


@dataclass
class ProbeDefinition:
    """Describes a single tracing probe to attach to the system."""

    probe_type: ProbeType
    target: str
    filter_expr: str = ""
    fields: list[str] = field(default_factory=list)
    entry: bool = True
    exit: bool = True


@dataclass
class ProbeHandle:
    """Opaque handle returned when a probe is successfully attached."""

    handle_id: str
    probe: ProbeDefinition


@dataclass
class TraceEvent:
    """A single event captured by a :class:`SystemTracer`."""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp_ns: int = 0
    wall_clock_ns: int = 0
    category: EventCategory = EventCategory.SYSCALL_RAW
    severity: EventSeverity = EventSeverity.INFO
    source: EventSource | None = None
    process: ProcessContext | None = None
    syscall_name: str = ""
    syscall_nr: int = -1
    args: dict = field(default_factory=dict)
    return_value: int | None = None
    latency_ns: int = 0
    tags: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# ABC
# ------------------------------------------------------------------


class SystemTracer(ABC):
    """Abstract interface for kernel / user-space tracing backends
    (eBPF, DTrace, ETW, etc.)."""

    @abstractmethod
    def attach(self, probe: ProbeDefinition) -> ProbeHandle:
        """Attach *probe* to the running system and return a handle."""

    @abstractmethod
    def detach(self, handle: ProbeHandle) -> None:
        """Detach a previously attached probe."""

    @abstractmethod
    def start(self) -> None:
        """Begin collecting events from all attached probes."""

    @abstractmethod
    def stop(self) -> None:
        """Stop event collection."""

    @abstractmethod
    def poll_events(
        self,
        timeout: float | None = None,
    ) -> Iterator[TraceEvent]:
        """Yield events, optionally blocking up to *timeout* seconds."""

    @abstractmethod
    def supported_probe_types(self) -> list[ProbeType]:
        """Return the probe types this tracer can handle."""
