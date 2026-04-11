"""Trace event data models."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Any
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext


@dataclass(slots=True)
class MonitorEvent:
    """Universal event type for all monitoring backends."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp_ns: int = 0
    wall_clock_ns: int = 0
    category: EventCategory = EventCategory.SYSCALL_RAW
    severity: EventSeverity = EventSeverity.INFO
    source: EventSource | None = None
    process: ProcessContext | None = None
    syscall_name: str = ""
    syscall_nr: int = -1
    args: dict[str, Any] = field(default_factory=dict)
    return_value: int | None = None
    latency_ns: int = 0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
