"""Abstract monitor backend protocol."""
from __future__ import annotations
from typing import Protocol, AsyncIterator, runtime_checkable
from dataclasses import dataclass, field
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr, FilterRule
from deepview.core.types import EventCategory, ProbeType


@dataclass
class ProbeSpec:
    """Platform-independent probe definition."""
    category: EventCategory
    probe_type: ProbeType = ProbeType.SYSCALL
    target: str = ""
    entry: bool = True
    exit: bool = True
    filter_expr: FilterExpr | None = None


@dataclass
class FilterPushDownResult:
    pushed: list[FilterRule] = field(default_factory=list)
    remaining: list[FilterRule] = field(default_factory=list)


@dataclass
class BackendStats:
    events_received: int = 0
    events_dropped: int = 0
    buffer_utilization: float = 0.0
    uptime_seconds: float = 0.0


@runtime_checkable
class MonitorBackend(Protocol):
    """Every platform monitoring backend implements this protocol."""

    @property
    def platform(self) -> str: ...

    @property
    def backend_name(self) -> str: ...

    async def start(self, probes: list[ProbeSpec]) -> None: ...

    async def stop(self) -> None: ...

    async def events(self) -> AsyncIterator[MonitorEvent]: ...

    def apply_filter(self, filter_expr: FilterExpr) -> FilterPushDownResult: ...

    def get_stats(self) -> BackendStats: ...
