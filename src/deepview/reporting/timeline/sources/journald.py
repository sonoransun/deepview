"""systemd-journal source via ``journalctl -o json``."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any, Iterator

from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent


class JournaldSource:
    source_type = SourceType.JOURNALD

    def __init__(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        host_id: str = "localhost",
    ) -> None:
        self.since = since
        self.until = until
        self.host_id = host_id

    def events(self) -> Iterator[TimelineEvent]:
        cmd = ["journalctl", "-o", "json", "--no-pager"]
        if self.since:
            cmd.extend(["--since", self.since])
        if self.until:
            cmd.extend(["--until", self.until])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        except Exception:
            return
        for line in proc.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield from self._parse(record)

    def _parse(self, record: dict[str, Any]) -> Iterator[TimelineEvent]:
        usec_str = record.get("__REALTIME_TIMESTAMP")
        if not usec_str:
            return
        try:
            usec = int(usec_str)
        except ValueError:
            return
        ts = datetime.fromtimestamp(usec / 1e6, tz=timezone.utc)
        priority = int(record.get("PRIORITY", 6))
        severity = Severity.LOW if priority <= 4 else Severity.INFO
        pid = int(record.get("_PID", 0)) if str(record.get("_PID", "")).isdigit() else 0
        comm = str(record.get("_COMM", ""))
        unit = str(record.get("_SYSTEMD_UNIT", ""))
        message = str(record.get("MESSAGE", ""))
        yield TimelineEvent(
            timestamp_utc=ts,
            timestamp_source="wall",
            host_id=self.host_id,
            entity_id=f"process:{pid}" if pid else "",
            source=SourceType.JOURNALD,
            description=f"{unit}: {message}"[:200] if unit else message[:200],
            severity=severity,
            pid=pid,
            process_comm=comm,
            raw={"unit": unit, "priority": priority},
        )
