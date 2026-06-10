"""Anomaly detection for memory forensics.

Heuristic feature scoring is always available with no third-party
dependency. When the ``ml`` extra (scikit-learn) is installed and a
baseline has been fitted via :meth:`AnomalyDetector.fit`, an
IsolationForest contributes an outlier score that is blended with the
heuristic (the heuristic stays a floor, so ML only ever raises a score).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("detection.anomaly")

# Stable feature ordering for the ML feature matrix.
_ML_FEATURES = (
    "vad_count",
    "rwx_vad_count",
    "module_count",
    "unknown_module_count",
    "thread_count",
    "handle_count",
    "private_memory_mb",
    "heap_entropy",
)


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

    def __init__(
        self,
        use_ml: bool = False,
        rwx_weight: float = 0.15,
        rwx_cap: float = 0.4,
        unknown_mod_weight: float = 0.1,
        unknown_mod_cap: float = 0.3,
        entropy_threshold: float = 7.5,
        entropy_score: float = 0.2,
        handle_threshold: int = 10000,
        handle_score: float = 0.1,
    ):
        self._use_ml = use_ml
        self._model = None
        self._rwx_weight = rwx_weight
        self._rwx_cap = rwx_cap
        self._unknown_mod_weight = unknown_mod_weight
        self._unknown_mod_cap = unknown_mod_cap
        self._entropy_threshold = entropy_threshold
        self._entropy_score = entropy_score
        self._handle_threshold = handle_threshold
        self._handle_score = handle_score

        self._fitted = False

        if use_ml:
            try:
                from sklearn.ensemble import IsolationForest
                self._model = IsolationForest(contamination=0.1, random_state=42)
                log.info("ml_model_initialized", model="IsolationForest")
            except ImportError:
                log.debug("scikit_learn_not_installed")
                self._use_ml = False

    def fit(self, processes: list[dict]) -> bool:
        """Train the IsolationForest on a baseline of normal processes.

        Returns ``True`` if a model was fitted (ML enabled, scikit-learn
        present, and enough samples), ``False`` otherwise — callers fall
        back to the heuristic transparently.
        """
        if not self._use_ml or self._model is None or len(processes) < 2:
            return False
        matrix = [
            [float(self.extract_features(p).get(f, 0) or 0) for f in _ML_FEATURES]
            for p in processes
        ]
        try:
            self._model.fit(matrix)
        except Exception as e:  # noqa: BLE001 - bad data shouldn't crash the caller
            log.warning("anomaly_fit_failed", error=str(e))
            return False
        self._fitted = True
        log.info("anomaly_model_fitted", samples=len(processes))
        return True

    def _ml_score(self, features: dict) -> float:
        """IsolationForest outlier score mapped to 0..1 (0 when unavailable)."""
        if not self._fitted or self._model is None:
            return 0.0
        vector = [[float(features.get(f, 0) or 0) for f in _ML_FEATURES]]
        try:
            decision = float(self._model.decision_function(vector)[0])
        except Exception:  # noqa: BLE001
            return 0.0
        # decision_function: positive == inlier, negative == outlier.
        return max(0.0, min(1.0, 0.5 - decision))

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
            score += min(rwx * self._rwx_weight, self._rwx_cap)

        # Unknown modules are suspicious
        unknown = features.get("unknown_module_count", 0)
        if unknown > 0:
            score += min(unknown * self._unknown_mod_weight, self._unknown_mod_cap)

        # Very high heap entropy may indicate encryption/packing
        entropy = features.get("heap_entropy", 0.0)
        if entropy > self._entropy_threshold:
            score += self._entropy_score

        # Extremely high handle count may indicate handle abuse
        handles = features.get("handle_count", 0)
        if handles > self._handle_threshold:
            score += self._handle_score

        return min(score, 1.0)

    def score_process(self, process: dict) -> AnomalyScore:
        """Score a single process for anomalies."""
        features = self.extract_features(process)
        heuristic = self.score_heuristic(features)
        ml = self._ml_score(features)
        # The heuristic is a floor; ML can only raise the score.
        score = max(heuristic, ml)

        explanations = []
        if features.get("rwx_vad_count", 0) > 0:
            explanations.append(f"{features['rwx_vad_count']} RWX memory regions")
        if features.get("unknown_module_count", 0) > 0:
            explanations.append(f"{features['unknown_module_count']} unknown modules")
        if features.get("heap_entropy", 0) > self._entropy_threshold:
            explanations.append("high heap entropy")
        if ml > heuristic:
            explanations.append(f"ML outlier ({ml:.2f})")

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

    def record_findings(
        self,
        context: AnalysisContext,
        processes: list[dict],
        *,
        threshold: float = 0.6,
    ) -> int:
        """Score processes and emit a :class:`Finding` for each anomaly.

        Closes the gap where detection results never reached the
        ``EventBus``: every process at or above *threshold* becomes a
        finding (published via ``context.add_finding``). Returns the count.
        """
        from deepview.core.findings import Finding
        from deepview.core.types import EventSeverity

        emitted = 0
        for score in self.score_processes(processes):
            if score.score < threshold:
                continue
            severity = EventSeverity.CRITICAL if score.score >= 0.8 else EventSeverity.WARNING
            context.add_finding(
                Finding(
                    name="anomalous_process",
                    title=f"Anomalous process {score.entity_name or score.entity_id}",
                    severity=severity,
                    category="anomaly",
                    description=score.explanation,
                    source="detection.anomaly",
                    pid=int(score.entity_id) if str(score.entity_id).isdigit() else 0,
                    process_name=score.entity_name,
                    evidence=dict(score.features),
                    confidence=score.score,
                )
            )
            emitted += 1
        return emitted
