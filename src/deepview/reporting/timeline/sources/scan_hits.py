"""YARA / pattern scan hits source."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Iterator

from deepview.core.types import ScanResult
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent


class ScanHitsSource:
    source_type = SourceType.SCAN

    def __init__(
        self,
        hits: Iterable[ScanResult],
        *,
        host_id: str = "localhost",
        observed_at: datetime | None = None,
    ) -> None:
        self.hits = list(hits)
        self.host_id = host_id
        self.observed_at = observed_at or datetime.now(timezone.utc)

    def events(self) -> Iterator[TimelineEvent]:
        for hit in self.hits:
            yield TimelineEvent(
                timestamp_utc=self.observed_at,
                timestamp_source="inferred",
                host_id=self.host_id,
                entity_id=f"scan:{hit.rule_name}:{hit.offset}",
                source=SourceType.SCAN,
                description=f"YARA hit {hit.rule_name} @ offset {hit.offset}",
                severity=Severity.MEDIUM,
                raw={"length": hit.length, **hit.metadata},
            )
