"""Tests for the unified Finding model and context wiring."""
from __future__ import annotations

from datetime import datetime, timezone

from deepview.core.context import AnalysisContext
from deepview.core.events import FindingEvent
from deepview.core.findings import FINDINGS_CATEGORY, Finding, severity_rank
from deepview.core.types import EventSeverity


class TestRoundTrip:
    def test_to_from_artifact_is_lossless(self):
        f = Finding(
            name="injected_code",
            title="Injected code in PID 1234",
            severity=EventSeverity.CRITICAL,
            category="injection",
            description="anonymous RWX region",
            source="detection.injection",
            attack_ids=["T1055"],
            timestamp=datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc),
            pid=1234,
            process_name="evil",
            evidence={"addr": "0x4000"},
            confidence=0.9,
        )
        restored = Finding.from_artifact(f.to_artifact())
        assert restored.name == f.name
        assert restored.severity == EventSeverity.CRITICAL
        assert restored.attack_ids == ["T1055"]
        assert restored.technique == "T1055"
        assert restored.pid == 1234
        assert restored.evidence == {"addr": "0x4000"}
        assert restored.timestamp == f.timestamp

    def test_artifact_shape_is_detection_compatible(self):
        # Keys the report's _detections_from_artifacts bridge reads.
        art = Finding(name="dkom", title="DKOM", attack_ids=["T1014"]).to_artifact()
        for key in ("name", "severity", "description", "pid", "process_name", "technique"):
            assert key in art
        assert art["technique"] == "T1014"

    def test_from_artifact_recovers_technique_when_no_attack_ids(self):
        f = Finding.from_artifact({"name": "x", "technique": "T1003"})
        assert f.attack_ids == ["T1003"]


class TestSeverityRank:
    def test_ordering(self):
        assert severity_rank(EventSeverity.CRITICAL) > severity_rank(EventSeverity.WARNING)
        assert severity_rank(EventSeverity.WARNING) > severity_rank(EventSeverity.INFO)


class TestContextWiring:
    def test_add_finding_stores_and_publishes(self):
        ctx = AnalysisContext.for_testing()
        captured: list[FindingEvent] = []
        ctx.events.subscribe(FindingEvent, captured.append)

        ctx.add_finding(
            Finding(name="rootkit", title="Rootkit", severity=EventSeverity.CRITICAL)
        )

        stored = ctx.artifacts.get(FINDINGS_CATEGORY)
        assert len(stored) == 1
        assert stored[0]["name"] == "rootkit"
        assert len(captured) == 1
        assert captured[0].name == "rootkit"
        assert captured[0].severity == "critical"
