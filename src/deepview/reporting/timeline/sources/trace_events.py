"""Trace event source — consumes ``MonitorEvent`` from a list or event bus."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from deepview.core.types import EventCategory, EventSeverity
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent
from deepview.tracing.events import MonitorEvent


class TraceEventSource:
    """Ingests a list (or iterable) of :class:`MonitorEvent` objects."""

    source_type = SourceType.TRACE

    def __init__(self, events: list[MonitorEvent] | None = None, host_id: str = "localhost") -> None:
        self._events: list[MonitorEvent] = list(events or [])
        self.host_id = host_id

    def add(self, event: MonitorEvent) -> None:
        self._events.append(event)

    def events(self) -> Iterator[TimelineEvent]:
        for monitor_event in self._events:
            yield self._translate(monitor_event)

    def _translate(self, me: MonitorEvent) -> TimelineEvent:
        # Prefer wall_clock_ns when provided; fall back to timestamp_ns
        ts_ns = me.wall_clock_ns or me.timestamp_ns
        if ts_ns == 0:
            ts = datetime.now(timezone.utc)
            source_kind = "inferred"
        else:
            ts = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
            source_kind = "wall" if me.wall_clock_ns else "monotonic"
        description = self._describe(me)
        return TimelineEvent(
            timestamp_utc=ts,
            timestamp_source=source_kind,
            host_id=self.host_id,
            entity_id=f"process:{me.process.pid}" if me.process else "",
            source=SourceType.TRACE,
            description=description,
            severity=self._severity(me),
            pid=me.process.pid if me.process else 0,
            process_comm=me.process.comm if me.process else "",
            raw=dict(me.args),
        )

    def _describe(self, me: MonitorEvent) -> str:
        if me.category is EventCategory.PROCESS_EXEC:
            argv = " ".join(me.args.get("argv", [])) if me.args else ""
            return f"exec {argv}".strip()
        if me.category is EventCategory.FILE_ACCESS:
            return f"{me.args.get('operation', 'open')} {me.args.get('path', '')}"
        if me.category is EventCategory.NETWORK_CONNECT:
            return (
                f"connect {me.args.get('protocol', 'tcp')} "
                f"{me.args.get('dst_ip', '?')}:{me.args.get('dst_port', '?')}"
            )
        if me.category is EventCategory.CRED_TRANSITION:
            return f"cred transition uid {me.args.get('old_uid', '?')}->{me.args.get('new_uid', '?')}"
        if me.category is EventCategory.MODULE_LOAD:
            return f"module load {me.args.get('name', '?')}"
        if me.category is EventCategory.PTRACE:
            return f"ptrace -> pid {me.args.get('target_pid', '?')}"
        return me.syscall_name or me.category.value

    def _severity(self, me: MonitorEvent) -> Severity:
        mapping = {
            EventSeverity.INFO: Severity.INFO,
            EventSeverity.WARNING: Severity.MEDIUM,
            EventSeverity.CRITICAL: Severity.CRITICAL,
        }
        return mapping.get(me.severity, Severity.INFO)
