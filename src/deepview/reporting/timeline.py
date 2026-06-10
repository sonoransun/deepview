"""Cross-artifact temporal correlation."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from deepview.core.logging import get_logger

log = get_logger("reporting.timeline")


@dataclass
class TimelineEntry:
    """A single event on the timeline."""
    timestamp: datetime
    event_type: str
    description: str
    source: str  # "memory", "trace", "instrumentation", "scan"
    severity: str = "info"
    pid: int = 0
    metadata: dict = field(default_factory=dict)


class TimelineBuilder:
    """Build and correlate timelines from multiple artifact sources."""

    def __init__(self):
        self._entries: list[TimelineEntry] = []

    def add_entry(self, entry: TimelineEntry) -> None:
        self._entries.append(entry)

    def add_entries(self, entries: list[TimelineEntry]) -> None:
        self._entries.extend(entries)

    def build(self) -> list[TimelineEntry]:
        """Return timeline sorted by timestamp."""
        return sorted(self._entries, key=lambda e: e.timestamp)

    def filter_by_pid(self, pid: int) -> list[TimelineEntry]:
        return sorted(
            [e for e in self._entries if e.pid == pid],
            key=lambda e: e.timestamp,
        )

    def filter_by_source(self, source: str) -> list[TimelineEntry]:
        return sorted(
            [e for e in self._entries if e.source == source],
            key=lambda e: e.timestamp,
        )

    def filter_by_severity(self, severity: str) -> list[TimelineEntry]:
        return sorted(
            [e for e in self._entries if e.severity == severity],
            key=lambda e: e.timestamp,
        )

    def to_dict_list(self) -> list[dict]:
        """Convert timeline to a list of dicts for serialization."""
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
        """Count entries per fixed-width time bucket across the full span.

        Returns one ``(bucket_start, count)`` pair per bucket including
        empty buckets, so a renderer can draw gaps as gaps.
        """
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
        # Guard against pathological spans producing unbounded buckets.
        max_buckets = 100_000
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
