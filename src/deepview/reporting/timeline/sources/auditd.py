"""auditd log source."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent


_TIMESTAMP_RE = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")
_KV_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_-]*)=("([^"]*)"|(\S+))')


class AuditdSource:
    source_type = SourceType.AUDITD

    def __init__(self, log_paths: Iterable[Path | str], host_id: str = "localhost") -> None:
        self.log_paths = [Path(p) for p in log_paths]
        self.host_id = host_id

    def events(self) -> Iterator[TimelineEvent]:
        for path in self.log_paths:
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                yield from self._parse(line)

    def _parse(self, line: str) -> Iterator[TimelineEvent]:
        m = _TIMESTAMP_RE.search(line)
        if not m:
            return
        ts_raw = float(m.group(1))
        fields: dict[str, str] = {}
        for km in _KV_RE.finditer(line):
            key = km.group(1)
            value = km.group(3) or km.group(4) or ""
            fields[key] = value
        type_ = fields.get("type", "")
        pid = int(fields.get("pid", 0)) if fields.get("pid", "").isdigit() else 0
        comm = fields.get("comm", "").strip('"')
        desc = f"{type_} {fields.get('exe', '')}".strip()
        yield TimelineEvent(
            timestamp_utc=datetime.fromtimestamp(ts_raw, tz=timezone.utc),
            timestamp_source="wall",
            host_id=self.host_id,
            entity_id=f"process:{pid}" if pid else "",
            source=SourceType.AUDITD,
            description=desc,
            severity=Severity.LOW,
            pid=pid,
            process_comm=comm,
            raw=fields,
        )
