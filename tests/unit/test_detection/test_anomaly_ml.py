"""Tests for the anomaly detector ML wiring and finding emission."""
from __future__ import annotations

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.events import FindingEvent
from deepview.core.findings import FINDINGS_CATEGORY
from deepview.detection.anomaly import AnomalyDetector


class TestFindingEmission:
    def test_record_findings_emits_for_anomalies(self):
        ctx = AnalysisContext.for_testing()
        captured: list[FindingEvent] = []
        ctx.events.subscribe(FindingEvent, captured.append)

        detector = AnomalyDetector()
        processes = [
            {"pid": 1, "name": "calm", "rwx_vad_count": 0},
            {"pid": 2, "name": "evil", "rwx_vad_count": 5, "unknown_module_count": 4},
        ]
        emitted = detector.record_findings(ctx, processes, threshold=0.3)

        assert emitted == 1
        stored = ctx.artifacts.get(FINDINGS_CATEGORY)
        assert len(stored) == 1
        assert stored[0]["process_name"] == "evil"
        assert stored[0]["category"] == "anomaly"
        assert captured[0].name == "anomalous_process"

    def test_heuristic_only_when_ml_disabled(self):
        detector = AnomalyDetector(use_ml=False)
        # fit is a no-op without ML.
        assert detector.fit([{"rwx_vad_count": 0}, {"rwx_vad_count": 0}]) is False
        score = detector.score_process({"pid": 9, "rwx_vad_count": 3})
        assert score.score > 0


class TestIsolationForest:
    def test_ml_raises_score_on_outlier(self):
        pytest.importorskip("sklearn")
        detector = AnomalyDetector(use_ml=True)
        baseline = [
            {"vad_count": 10, "thread_count": 4, "handle_count": 50, "rwx_vad_count": 0}
            for _ in range(40)
        ]
        assert detector.fit(baseline) is True
        # A wildly different process should score as an ML outlier even
        # though the heuristic alone (no rwx/unknown modules) would be low.
        outlier = {"vad_count": 9000, "thread_count": 900, "handle_count": 90000, "rwx_vad_count": 0}
        score = detector.score_process(outlier)
        assert score.score > 0.0
