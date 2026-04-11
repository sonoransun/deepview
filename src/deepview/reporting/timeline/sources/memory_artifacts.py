"""Memory-analysis artifacts source."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent


class MemoryArtifactSource:
    """Reads from an :class:`AnalysisContext`'s artifact store."""

    source_type = SourceType.MEMORY

    #: Artifact categories whose items are expected to have a ``timestamp``
    #: or ``CreateTime`` field.
    _TIME_KEYS = ("timestamp", "CreateTime", "create_time", "last_modified")

    def __init__(
        self,
        artifacts: dict[str, list[dict[str, Any]]],
        host_id: str = "localhost",
    ) -> None:
        self._artifacts = artifacts
        self.host_id = host_id

    def events(self) -> Iterator[TimelineEvent]:
        for category, items in self._artifacts.items():
            for item in items:
                ts = self._resolve_timestamp(item)
                if ts is None:
                    continue
                pid = int(item.get("pid", 0)) if isinstance(item.get("pid"), (int, str)) and str(item.get("pid")).isdigit() else 0
                yield TimelineEvent(
                    timestamp_utc=ts,
                    timestamp_source="wall",
                    host_id=self.host_id,
                    entity_id=f"process:{pid}" if pid else "",
                    source=SourceType.MEMORY,
                    description=f"{category}: {item.get('name') or item.get('description') or ''}".strip(": "),
                    severity=Severity.INFO,
                    pid=pid,
                    process_comm=str(item.get("comm") or item.get("process") or ""),
                    raw=dict(item),
                )

    def _resolve_timestamp(self, item: dict[str, Any]) -> datetime | None:
        for key in self._TIME_KEYS:
            value = item.get(key)
            if value is None:
                continue
            if isinstance(value, datetime):
                return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value).astimezone(timezone.utc)
                except ValueError:
                    continue
        return None
