"""The timeline merger.

Streams events from every registered :class:`Source`, normalises
timestamps, deduplicates, sorts, and returns a merged list of
:class:`TimelineEvent`. Also exposes the legacy ``TimelineBuilder`` alias
for backwards compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Protocol

from deepview.core.logging import get_logger
from deepview.reporting.timeline.event import (
    Severity,
    SourceType,
    TimelineEntry,
    TimelineEvent,
)

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
    """Legacy builder over flat :class:`TimelineEntry` rows.

    This is the drop-in replacement for the old ``reporting/timeline.py``
    ``TimelineBuilder``: it stores raw ``TimelineEntry`` objects (string
    ``source``/``severity``, wall-clock ``timestamp``) and exposes the
    build / aggregation surface the CLI ``report timeline`` command, the
    HTML report visuals, and third-party callers rely on. New multi-source
    work should use :class:`TimelineMerger` + :class:`TimelineEvent`.
    """

    def __init__(self) -> None:
        self._entries: list[TimelineEntry] = []

    def add_entry(self, entry: TimelineEntry) -> None:
        # Accept a rich TimelineEvent too, downgrading it to the flat shape.
        if isinstance(entry, TimelineEvent):
            entry = TimelineEntry(
                timestamp=entry.timestamp_utc,
                event_type=entry.source.value,
                description=entry.description,
                source=entry.source.value,
                severity=entry.severity.value,
                pid=entry.pid,
                metadata=dict(entry.raw),
            )
        self._entries.append(entry)

    def add_entries(self, entries: Iterable[TimelineEntry]) -> None:
        for e in entries:
            self.add_entry(e)

    def build(self) -> list[TimelineEntry]:
        """Return entries sorted by timestamp."""
        return sorted(self._entries, key=lambda e: e.timestamp)

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "description": e.description,
                "source": e.source,
                "severity": e.severity,
                "pid": e.pid,
            }
            for e in self.build()
        ]

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def filter_by_pid(self, pid: int) -> list[TimelineEntry]:
        return [e for e in self.build() if e.pid == pid]

    def filter_by_source(self, source: str) -> list[TimelineEntry]:
        return [e for e in self.build() if e.source == source]

    def filter_by_severity(self, severity: str) -> list[TimelineEntry]:
        return [e for e in self.build() if e.severity == severity]

    # ------------------------------------------------------------------
    # Aggregation (powers the CLI swimlane and the HTML report timeline)
    # ------------------------------------------------------------------

    def span(self) -> tuple[datetime, datetime] | None:
        """Earliest and latest entry timestamps, or ``None`` when empty."""
        ordered = self.build()
        if not ordered:
            return None
        return ordered[0].timestamp, ordered[-1].timestamp

    def bucketed(self, bucket_s: float) -> list[tuple[datetime, int]]:
        """Count entries per fixed-width time bucket across the full span."""
        if bucket_s <= 0:
            raise ValueError("bucket_s must be positive")
        span = self.span()
        if span is None:
            return []
        start, end = span
        step = timedelta(seconds=bucket_s)
        buckets: list[tuple[datetime, int]] = []
        ordered = self.build()
        edge = start
        idx = 0
        max_buckets = 100_000  # guard against pathological spans
        while edge <= end and len(buckets) < max_buckets:
            nxt = edge + step
            count = 0
            while idx < len(ordered) and ordered[idx].timestamp < nxt:
                count += 1
                idx += 1
            buckets.append((edge, count))
            edge = nxt
        return buckets

    def gaps(self, min_gap_s: float) -> list[tuple[datetime, datetime, float]]:
        """Quiet intervals ``>= min_gap_s`` between consecutive entries."""
        ordered = self.build()
        out: list[tuple[datetime, datetime, float]] = []
        for prev, cur in zip(ordered, ordered[1:]):
            delta = (cur.timestamp - prev.timestamp).total_seconds()
            if delta >= min_gap_s:
                out.append((prev.timestamp, cur.timestamp, delta))
        return out

    def lanes(self, by: str = "source") -> dict[str, list[TimelineEntry]]:
        """Group sorted entries into lanes keyed by ``source`` or ``severity``."""
        if by not in ("source", "severity"):
            raise ValueError("lanes(by=) must be 'source' or 'severity'")
        lanes: dict[str, list[TimelineEntry]] = {}
        for entry in self.build():
            key = getattr(entry, by)
            lanes.setdefault(str(key), []).append(entry)
        return lanes
