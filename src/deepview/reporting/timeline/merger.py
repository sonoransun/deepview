"""The timeline merger.

Streams events from every registered :class:`Source`, normalises
timestamps, deduplicates, sorts, and returns a merged list of
:class:`TimelineEvent`. Also exposes the legacy ``TimelineBuilder`` alias
for backwards compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Protocol

from deepview.core.logging import get_logger
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent

log = get_logger("reporting.timeline.merger")


class TimelineSource(Protocol):
    """Any object that yields :class:`TimelineEvent`."""

    source_type: SourceType

    def events(self) -> Iterator[TimelineEvent]:
        ...


@dataclass
class ClockOffsets:
    """Per-host clock offsets vs a reference clock.

    Positive ``wall_minus_reference_ns`` means the host's wall clock is
    ahead of the reference. Monotonic boot anchor lets the merger promote
    monotonic timestamps into wall-clock time.
    """

    wall_minus_reference_ns: dict[str, int] = field(default_factory=dict)
    boot_wall_ns: dict[str, int] = field(default_factory=dict)

    def normalise(self, event: TimelineEvent) -> TimelineEvent:
        offset = self.wall_minus_reference_ns.get(event.host_id, 0)
        if event.timestamp_source == "monotonic":
            boot = self.boot_wall_ns.get(event.host_id)
            if boot is None:
                return event  # cannot reconcile
            event_ns = int(event.timestamp_utc.timestamp() * 1e9)
            abs_ns = boot + event_ns
            return event.model_copy(
                update={
                    "timestamp_utc": datetime.fromtimestamp(abs_ns / 1e9, tz=timezone.utc),
                    "timestamp_source": "wall",
                }
            )
        if offset != 0:
            return event.model_copy(
                update={
                    "timestamp_utc": datetime.fromtimestamp(
                        event.timestamp_utc.timestamp() - offset / 1e9,
                        tz=timezone.utc,
                    )
                }
            )
        return event


class TimelineMerger:
    """Multi-source timeline merger with clock reconciliation + dedup."""

    def __init__(self, clocks: ClockOffsets | None = None) -> None:
        self._sources: list[TimelineSource] = []
        self._clocks = clocks or ClockOffsets()

    def add_source(self, source: TimelineSource) -> None:
        self._sources.append(source)

    def build(self) -> list[TimelineEvent]:
        collected: list[TimelineEvent] = []
        for src in self._sources:
            try:
                for event in src.events():
                    collected.append(self._clocks.normalise(event))
            except Exception:
                log.exception("source_failed", source=getattr(src, "source_type", "?"))
        return self._dedup_and_sort(collected)

    def _dedup_and_sort(self, events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
        seen: dict[tuple[str, str, int, str], TimelineEvent] = {}
        for event in events:
            key = event.dedup_key()
            existing = seen.get(key)
            if existing is None:
                seen[key] = event
                continue
            # Merge: prefer higher severity, longer description, merged MITRE
            merged = existing.model_copy(
                update={
                    "severity": _max_severity(existing.severity, event.severity),
                    "mitre_techniques": sorted(
                        set(existing.mitre_techniques) | set(event.mitre_techniques)
                    ),
                    "description": (
                        existing.description
                        if len(existing.description) >= len(event.description)
                        else event.description
                    ),
                    "graph_edges": sorted(set(existing.graph_edges) | set(event.graph_edges)),
                }
            )
            seen[key] = merged
        return sorted(seen.values(), key=lambda e: (e.timestamp_utc, e.description))


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _max_severity(a: Severity, b: Severity) -> Severity:
    return max(a, b, key=_SEVERITY_ORDER.index)


# ---------------------------------------------------------------------------
# Backwards-compat alias
# ---------------------------------------------------------------------------


class TimelineBuilder:
    """Legacy API that accepts raw ``TimelineEntry`` objects."""

    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []

    def add_entry(self, entry) -> None:  # type: ignore[no-untyped-def]
        from deepview.reporting.timeline.event import TimelineEntry

        if isinstance(entry, TimelineEntry):
            self._events.append(entry.to_timeline_event())
        elif isinstance(entry, TimelineEvent):
            self._events.append(entry)
        else:
            raise TypeError(f"Unsupported entry type: {type(entry).__name__}")

    def add_entries(self, entries: Iterable[Any]) -> None:
        for e in entries:
            self.add_entry(e)

    def build(self) -> list[TimelineEvent]:
        return sorted(self._events, key=lambda e: e.timestamp_utc)

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [e.model_dump(mode="json") for e in self.build()]

    @property
    def entry_count(self) -> int:
        return len(self._events)

    def filter_by_pid(self, pid: int) -> list[TimelineEvent]:
        return [e for e in self.build() if e.pid == pid]

    def filter_by_source(self, source: str) -> list[TimelineEvent]:
        return [e for e in self.build() if e.source.value == source]

    def filter_by_severity(self, severity: str) -> list[TimelineEvent]:
        return [e for e in self.build() if e.severity.value == severity]
