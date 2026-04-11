"""Filesystem MACB source.

Walks a list of paths and emits one :class:`TimelineEvent` per
``{path, mtime/ctime/atime/crtime}``. Optionally runs the
:class:`TimestompingDetector` and emits additional critical rows for any
timestomp findings.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent
from deepview.reporting.timeline.timestomping import FileTimes, TimestompingDetector


class FilesystemSource:
    source_type = SourceType.FILESYSTEM

    def __init__(
        self,
        paths: Iterable[Path | str],
        *,
        host_id: str = "localhost",
        detect_timestomping: bool = True,
    ) -> None:
        self.paths = [Path(p) for p in paths]
        self.host_id = host_id
        self.detect_timestomping = detect_timestomping

    def events(self) -> Iterator[TimelineEvent]:
        detector = TimestompingDetector() if self.detect_timestomping else None
        for path in self.paths:
            try:
                stat = path.stat()
            except OSError:
                continue
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            ctime = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
            atime = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc)
            for label, ts in (("mtime", mtime), ("ctime", ctime), ("atime", atime)):
                yield TimelineEvent(
                    timestamp_utc=ts,
                    timestamp_source="wall",
                    host_id=self.host_id,
                    entity_id=f"file:{path}",
                    source=SourceType.FILESYSTEM,
                    description=f"{label} {path}",
                    severity=Severity.INFO,
                    raw={"stat_field": label, "size": stat.st_size},
                )
            if detector is not None:
                ft = FileTimes(path=str(path), mtime=mtime, ctime=ctime, atime=atime)
                for finding in detector.scan([ft]):
                    yield TimelineEvent(
                        timestamp_utc=mtime,
                        timestamp_source="wall",
                        host_id=self.host_id,
                        entity_id=f"file:{path}",
                        source=SourceType.FILESYSTEM,
                        description=f"TIMESTOMP: {finding.reason}",
                        severity=Severity(finding.severity)
                        if finding.severity in {s.value for s in Severity}
                        else Severity.MEDIUM,
                        mitre_techniques=["T1070.006"],
                        raw=dict(finding.evidence),
                    )
