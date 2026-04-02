"""ML-based anomaly detection for memory forensics (stub)."""
from __future__ import annotations
from dataclasses import dataclass, field
from deepview.core.logging import get_logger

log = get_logger("detection.anomaly")


@dataclass
class AnomalyScore:
    """Anomaly score for a process or memory region."""
    entity_id: str  # PID or address range
    entity_name: str
    score: float  # 0.0 (normal) to 1.0 (highly anomalous)
    features: dict = field(default_factory=dict)
    explanation: str = ""


class AnomalyDetector:
    """ML-based anomaly detection for memory artifacts.

    Feature extraction from memory:
    - VAD tree characteristics (count, protection distribution, size distribution)
    - Loaded module sets (known vs unknown modules)
    - Heap entropy per process
    - Handle counts and types
    - Thread count and start address distribution

    Models:
    - Isolation Forest for outlier detection
    - One-class SVM for boundary learning
    - Feature-based heuristic scoring (no ML dependency)
    """

    def __init__(self, use_ml: bool = False):
        self._use_ml = use_ml
        self._model = None

        if use_ml:
            try:
                from sklearn.ensemble import IsolationForest
                self._model = IsolationForest(contamination=0.1, random_state=42)
                log.info("ml_model_initialized", model="IsolationForest")
            except ImportError:
                log.debug("scikit_learn_not_installed")
                self._use_ml = False

    def extract_features(self, process: dict) -> dict:
        """Extract feature vector from process metadata."""
        return {
            "vad_count": process.get("vad_count", 0),
            "rwx_vad_count": process.get("rwx_vad_count", 0),
            "module_count": process.get("module_count", 0),
            "unknown_module_count": process.get("unknown_module_count", 0),
            "thread_count": process.get("thread_count", 0),
            "handle_count": process.get("handle_count", 0),
            "private_memory_mb": process.get("private_memory_mb", 0),
            "heap_entropy": process.get("heap_entropy", 0.0),
        }

    def score_heuristic(self, features: dict) -> float:
        """Score anomaly using heuristic rules (no ML required)."""
        score = 0.0

        # RWX memory regions are suspicious
        rwx = features.get("rwx_vad_count", 0)
        if rwx > 0:
            score += min(rwx * 0.15, 0.4)

        # Unknown modules are suspicious
        unknown = features.get("unknown_module_count", 0)
        if unknown > 0:
            score += min(unknown * 0.1, 0.3)

        # Very high heap entropy may indicate encryption/packing
        entropy = features.get("heap_entropy", 0.0)
        if entropy > 7.5:
            score += 0.2

        # Extremely high handle count may indicate handle abuse
        handles = features.get("handle_count", 0)
        if handles > 10000:
            score += 0.1

        return min(score, 1.0)

    def score_process(self, process: dict) -> AnomalyScore:
        """Score a single process for anomalies."""
        features = self.extract_features(process)
        score = self.score_heuristic(features)

        explanations = []
        if features.get("rwx_vad_count", 0) > 0:
            explanations.append(f"{features['rwx_vad_count']} RWX memory regions")
        if features.get("unknown_module_count", 0) > 0:
            explanations.append(f"{features['unknown_module_count']} unknown modules")
        if features.get("heap_entropy", 0) > 7.5:
            explanations.append("high heap entropy")

        return AnomalyScore(
            entity_id=str(process.get("pid", "")),
            entity_name=process.get("name", ""),
            score=score,
            features=features,
            explanation="; ".join(explanations) if explanations else "normal",
        )

    def score_processes(self, processes: list[dict]) -> list[AnomalyScore]:
        """Score multiple processes and rank by anomaly."""
        scores = [self.score_process(p) for p in processes]
        return sorted(scores, key=lambda s: s.score, reverse=True)
