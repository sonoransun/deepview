"""macOS unified log ingestion via ``log show --style=json``."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any, Iterator

from deepview.core.logging import get_logger
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent

log = get_logger("reporting.timeline.sources.unified_log")


class UnifiedLogSource:
    source_type = SourceType.UNIFIED_LOG

    def __init__(
        self,
        *,
        predicate: str = 'messageType == "Error"',
        start: str | None = None,
        end: str | None = None,
        host_id: str = "localhost",
    ) -> None:
        self.predicate = predicate
        self.start = start
        self.end = end
        self.host_id = host_id

    def events(self) -> Iterator[TimelineEvent]:
        cmd = ["log", "show", "--style", "json", "--predicate", self.predicate]
        if self.start:
            cmd += ["--start", self.start]
        if self.end:
            cmd += ["--end", self.end]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        except Exception:
            return
        try:
            records = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return
        for record in records or []:
            yield from self._parse(record)

    def _parse(self, record: dict[str, Any]) -> Iterator[TimelineEvent]:
        ts_str = record.get("timestamp")
        if not ts_str:
            return
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            return
        message = str(record.get("eventMessage", ""))
        subsystem = str(record.get("subsystem", ""))
        process = str(record.get("processImagePath", ""))
        pid = int(record.get("processID", 0)) if record.get("processID") else 0
        yield TimelineEvent(
            timestamp_utc=ts.astimezone(timezone.utc),
            timestamp_source="wall",
            host_id=self.host_id,
            entity_id=f"process:{pid}" if pid else "",
            source=SourceType.UNIFIED_LOG,
            description=f"{subsystem}: {message}"[:200],
            severity=Severity.INFO,
            pid=pid,
            process_comm=process.split("/")[-1],
            raw={"subsystem": subsystem},
        )
