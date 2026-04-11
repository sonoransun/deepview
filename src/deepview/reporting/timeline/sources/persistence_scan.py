"""Persistence scan source — takes a list of :class:`PersistenceArtifact`s."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Iterator

from deepview.detection.persistence.base import PersistenceArtifact, PersistenceSeverity
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent


class PersistenceSource:
    source_type = SourceType.PERSISTENCE

    def __init__(
        self,
        findings: Iterable[PersistenceArtifact],
        host_id: str = "localhost",
    ) -> None:
        self.findings = list(findings)
        self.host_id = host_id

    def events(self) -> Iterator[TimelineEvent]:
        for f in self.findings:
            ts = f.last_modified or datetime.now(timezone.utc)
            yield TimelineEvent(
                timestamp_utc=ts,
                timestamp_source="wall",
                host_id=self.host_id,
                entity_id=f"persist:{f.mechanism}:{f.location}",
                source=SourceType.PERSISTENCE,
                description=f"{f.mechanism} @ {f.location}",
                severity=_severity_map(f.severity),
                mitre_techniques=[f.mitre_technique] if f.mitre_technique else [],
                raw={
                    "command": f.command,
                    "reasons": list(f.suspicious_reasons),
                    "owner": f.owning_user,
                    "deviation": f.deviation_from_baseline,
                    "fingerprint": f.fingerprint(),
                },
            )


_SEV_MAP = {
    PersistenceSeverity.INFO: Severity.INFO,
    PersistenceSeverity.LOW: Severity.LOW,
    PersistenceSeverity.MEDIUM: Severity.MEDIUM,
    PersistenceSeverity.HIGH: Severity.HIGH,
    PersistenceSeverity.CRITICAL: Severity.CRITICAL,
}


def _severity_map(value: PersistenceSeverity) -> Severity:
    return _SEV_MAP.get(value, Severity.INFO)
