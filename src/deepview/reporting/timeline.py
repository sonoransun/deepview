"""Cross-artifact temporal correlation."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
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
