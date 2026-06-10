"""Unified forensic :class:`Finding` model.

Historically every producer (detection, classification, scanning) had its
own result type and only the classifier published onto the :class:`EventBus`.
A ``Finding`` is the one shape they can all share: it carries a stable short
``name`` (the detection identifier used by the ATT&CK mapper), a human
``title``, a :class:`EventSeverity`, MITRE ``attack_ids``, and the evidence
needed to triage it.

A ``Finding`` round-trips through the existing untyped
:class:`deepview.core.context.ArtifactStore` via :meth:`to_artifact` /
:meth:`from_artifact`, so the report exporters that already reconstruct
``Detection`` objects from artifact dicts keep working unchanged.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from deepview.core.types import EventSeverity

#: Artifact-store category that :meth:`AnalysisContext.add_finding` writes to.
FINDINGS_CATEGORY = "findings"

_SEVERITY_RANK = {
    EventSeverity.INFO: 0,
    EventSeverity.WARNING: 1,
    EventSeverity.CRITICAL: 2,
}


def severity_rank(severity: EventSeverity) -> int:
    """Ordinal rank for a severity (higher is worse)."""
    return _SEVERITY_RANK.get(severity, 0)


def coerce_severity(value: object) -> EventSeverity:
    """Best-effort coercion of an arbitrary value to :class:`EventSeverity`."""
    if isinstance(value, EventSeverity):
        return value
    try:
        return EventSeverity(str(value).lower())
    except ValueError:
        return EventSeverity.INFO


@dataclass
class Finding:
    """A single forensic finding shared across subsystems."""

    name: str
    title: str
    severity: EventSeverity = EventSeverity.INFO
    category: str = "generic"
    description: str = ""
    source: str = ""
    attack_ids: list[str] = field(default_factory=list)
    timestamp: datetime | None = None
    pid: int = 0
    process_name: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def technique(self) -> str:
        """Primary MITRE technique id, or empty when none is attached."""
        return self.attack_ids[0] if self.attack_ids else ""

    def to_artifact(self) -> dict[str, Any]:
        """Serialise to the plain-dict shape the artifact store holds.

        The keys ``name`` / ``severity`` / ``description`` / ``pid`` /
        ``process_name`` / ``technique`` / ``evidence`` are exactly what
        ``cli/commands/report.py::_detections_from_artifacts`` reads, and
        ``timestamp`` is what the timeline command consumes.
        """
        return {
            "id": self.id,
            "name": self.name,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "source": self.source,
            "attack_ids": list(self.attack_ids),
            "technique": self.technique,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "pid": self.pid,
            "process_name": self.process_name,
            "evidence": dict(self.evidence),
            "confidence": self.confidence,
        }

    @classmethod
    def from_artifact(cls, data: dict[str, Any]) -> Finding:
        """Reconstruct a :class:`Finding` from an artifact dict."""
        attack_ids = data.get("attack_ids")
        if not attack_ids and data.get("technique"):
            attack_ids = [str(data["technique"])]
        ts_raw = data.get("timestamp")
        timestamp: datetime | None = None
        if isinstance(ts_raw, datetime):
            timestamp = ts_raw
        elif isinstance(ts_raw, (int, float)):
            timestamp = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
        elif isinstance(ts_raw, str) and ts_raw:
            try:
                timestamp = datetime.fromisoformat(ts_raw)
            except ValueError:
                timestamp = None
        evidence = data.get("evidence")
        return cls(
            name=str(data.get("name", "finding")),
            title=str(data.get("title", data.get("name", "finding"))),
            severity=coerce_severity(data.get("severity", "info")),
            category=str(data.get("category", "generic")),
            description=str(data.get("description", "")),
            source=str(data.get("source", "")),
            attack_ids=[str(t) for t in (attack_ids or [])],
            timestamp=timestamp,
            pid=int(data.get("pid", 0) or 0),
            process_name=str(data.get("process_name", "")),
            evidence=evidence if isinstance(evidence, dict) else {},
            confidence=float(data.get("confidence", 1.0) or 0.0),
            id=str(data.get("id", uuid.uuid4().hex)),
        )
