"""Tests for deepview.detection.anomaly module."""
from __future__ import annotations

import pytest

from deepview.detection.anomaly import AnomalyDetector, AnomalyScore


class TestExtractFeatures:
    """Tests for AnomalyDetector.extract_features."""

    def test_extract_features_defaults(self):
        """Empty dict gives all zeros."""
        detector = AnomalyDetector()
        features = detector.extract_features({})

        assert features["vad_count"] == 0
        assert features["rwx_vad_count"] == 0
        assert features["module_count"] == 0
        assert features["unknown_module_count"] == 0
        assert features["thread_count"] == 0
        assert features["handle_count"] == 0
        assert features["private_memory_mb"] == 0
        assert features["heap_entropy"] == 0.0

    def test_extract_features_with_data(self):
        """Verify correct extraction of all feature fields."""
        detector = AnomalyDetector()
        process = {
            "vad_count": 42,
            "rwx_vad_count": 3,
            "module_count": 15,
            "unknown_module_count": 2,
            "thread_count": 8,
            "handle_count": 500,
            "private_memory_mb": 128,
            "heap_entropy": 6.5,
        }
        features = detector.extract_features(process)

        assert features["vad_count"] == 42
        assert features["rwx_vad_count"] == 3
        assert features["module_count"] == 15
        assert features["unknown_module_count"] == 2
        assert features["thread_count"] == 8
        assert features["handle_count"] == 500
        assert features["private_memory_mb"] == 128
        assert features["heap_entropy"] == 6.5


class TestScoreHeuristic:
    """Tests for AnomalyDetector.score_heuristic."""

    def test_score_heuristic_normal(self):
        """All zeros scores 0.0."""
        detector = AnomalyDetector()
        features = {
            "rwx_vad_count": 0,
            "unknown_module_count": 0,
            "heap_entropy": 0.0,
            "handle_count": 0,
        }
        assert detector.score_heuristic(features) == 0.0

    def test_score_heuristic_rwx_regions(self):
        """rwx_vad_count=2 should add 2*0.15 = 0.3."""
        detector = AnomalyDetector()
        features = {
            "rwx_vad_count": 2,
            "unknown_module_count": 0,
            "heap_entropy": 0.0,
            "handle_count": 0,
        }
        assert detector.score_heuristic(features) == pytest.approx(0.3)

    def test_score_heuristic_unknown_modules(self):
        """unknown_module_count=3 should add min(3*0.1, 0.3) = 0.3."""
        detector = AnomalyDetector()
        features = {
            "rwx_vad_count": 0,
            "unknown_module_count": 3,
            "heap_entropy": 0.0,
            "handle_count": 0,
        }
        assert detector.score_heuristic(features) == pytest.approx(0.3)

    def test_score_heuristic_high_entropy(self):
        """heap_entropy=8.0 (> 7.5) adds 0.2."""
        detector = AnomalyDetector()
        features = {
            "rwx_vad_count": 0,
            "unknown_module_count": 0,
            "heap_entropy": 8.0,
            "handle_count": 0,
        }
        assert detector.score_heuristic(features) == pytest.approx(0.2)

    def test_score_heuristic_high_handles(self):
        """handle_count=20000 (> 10000) adds 0.1."""
        detector = AnomalyDetector()
        features = {
            "rwx_vad_count": 0,
            "unknown_module_count": 0,
            "heap_entropy": 0.0,
            "handle_count": 20000,
        }
        assert detector.score_heuristic(features) == pytest.approx(0.1)

    def test_score_heuristic_combined_capped(self):
        """All indicators active; score capped at 1.0."""
        detector = AnomalyDetector()
        features = {
            "rwx_vad_count": 5,   # min(5*0.15, 0.4) = 0.4
            "unknown_module_count": 5,  # min(5*0.1, 0.3) = 0.3
            "heap_entropy": 8.0,        # 0.2
            "handle_count": 20000,      # 0.1
        }
        # 0.4 + 0.3 + 0.2 + 0.1 = 1.0
        assert detector.score_heuristic(features) == pytest.approx(1.0)


class TestScoreProcess:
    """Tests for AnomalyDetector.score_process."""

    def test_score_process(self):
        """Verify score_process returns AnomalyScore with correct fields."""
        detector = AnomalyDetector()
        process = {
            "pid": 1234,
            "name": "suspicious.exe",
            "rwx_vad_count": 1,
            "unknown_module_count": 0,
            "heap_entropy": 5.0,
            "handle_count": 100,
        }
        result = detector.score_process(process)

        assert isinstance(result, AnomalyScore)
        assert result.entity_id == "1234"
        assert result.entity_name == "suspicious.exe"
        assert result.score == pytest.approx(0.15)  # 1*0.15
        assert "rwx_vad_count" in result.features
        assert "1 RWX memory regions" in result.explanation


class TestScoreProcesses:
    """Tests for AnomalyDetector.score_processes."""

    def test_score_processes_sorted(self):
        """Verify results are sorted descending by score."""
        detector = AnomalyDetector()
        processes = [
            {"pid": 1, "name": "clean", "rwx_vad_count": 0, "unknown_module_count": 0},
            {"pid": 2, "name": "suspicious", "rwx_vad_count": 3, "unknown_module_count": 2},
            {"pid": 3, "name": "moderate", "rwx_vad_count": 1, "unknown_module_count": 0},
        ]
        results = detector.score_processes(processes)

        assert len(results) == 3
        assert results[0].entity_id == "2"
        assert results[-1].entity_id == "1"
        # Verify descending order
        for i in range(len(results) - 1):
            assert results[i].score >= results[i + 1].score
