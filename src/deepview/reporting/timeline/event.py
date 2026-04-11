"""Timeline event data model."""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(str, enum.Enum):
    TRACE = "trace"
    MEMORY = "memory"
    FILESYSTEM = "filesystem"
    AUDITD = "auditd"
    JOURNALD = "journald"
    EVTX = "evtx"
    UNIFIED_LOG = "unified_log"
    PERSISTENCE = "persistence"
    BASELINE = "baseline"
    SCAN = "scan"
    CORRELATION = "correlation"
    UNKNOWN = "unknown"


class TimelineEvent(BaseModel):
    """One row in the unified forensic timeline.

    Sources may provide either a wall-clock or a monotonic timestamp; the
    :class:`TimelineMerger` normalises both to UTC datetimes before sort.
    """

    timestamp_utc: datetime
    timestamp_source: str = "wall"  # "wall" | "monotonic" | "inferred"
    timestamp_confidence: float = 1.0
    host_id: str = "localhost"
    entity_id: str = ""
    source: SourceType = SourceType.UNKNOWN
    description: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    pid: int = 0
    process_comm: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    graph_edges: list[str] = Field(default_factory=list)  # links to correlation graph edge sigs

    def dedup_key(self) -> tuple[str, str, int, str]:
        return (
            self.host_id,
            self.entity_id,
            int(self.timestamp_utc.timestamp() * 1_000_000),
            self.description,
        )

    def bodyfile_line(self) -> str:
        """Render in plaso / Sleuth Kit bodyfile format.

        Format: ``MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime``
        We don't have inode/mode/etc. for every source, so most fields are 0
        — only the name and timestamps matter for psort.
        """
        epoch = int(self.timestamp_utc.timestamp())
        name = f"{self.source.value}:{self.description}"[:255]
        return f"0|{name}|0|0|0|0|0|{epoch}|{epoch}|{epoch}|{epoch}"


# ---------------------------------------------------------------------------
# Backwards-compatibility: pre-Gap 5 code referred to these names.
# ---------------------------------------------------------------------------


class TimelineEntry(BaseModel):
    """Legacy shim; new code should use :class:`TimelineEvent`."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = ""
    description: str = ""
    source: str = ""
    severity: str = "info"
    pid: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_timeline_event(self) -> TimelineEvent:
        return TimelineEvent(
            timestamp_utc=_ensure_utc(self.timestamp),
            host_id="localhost",
            entity_id=f"process:{self.pid}" if self.pid else "",
            source=_coerce_source(self.source),
            description=self.description or self.event_type,
            severity=_coerce_severity(self.severity),
            pid=self.pid,
            raw=dict(self.metadata),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_source(value: str) -> SourceType:
    try:
        return SourceType(value)
    except ValueError:
        return SourceType.UNKNOWN


def _coerce_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.INFO
