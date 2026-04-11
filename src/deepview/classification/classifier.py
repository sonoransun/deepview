"""Live :class:`EventClassifier` that sits on a TraceEventBus.

The classifier subscribes to an upstream :class:`TraceEventBus`,
evaluates every event against a :class:`Ruleset`, attaches the
results to ``event.metadata['classifications']``, and republishes:

* the decorated ``MonitorEvent`` onto a private classifier bus the
  caller can subscribe to (``classified_subscription``), and
* a typed :class:`EventClassifiedEvent` for each rule hit into the
  core :class:`EventBus` so other subsystems (timeline, replay,
  auto-inspector) can react.

On top of rule matching, the classifier maintains a small sliding-
window aggregator per PID and forwards a feature vector to the
static heuristic scorer in :mod:`deepview.detection.anomaly`. Hits
with elevated anomaly scores are published alongside the rule hits.
"""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deepview.classification.ruleset import Ruleset
from deepview.core.events import EventClassifiedEvent
from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import EventSubscription, TraceEventBus

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("classification.classifier")


@dataclass
class ClassificationResult:
    """One rule match attached to an event."""

    rule_id: str
    title: str
    severity: str
    category: str
    attack_ids: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    anomaly_score: float = 0.0


@dataclass
class _PidWindow:
    """Rolling per-PID event counters used by the anomaly bridge."""

    syscalls: int = 0
    unique_paths: set[str] = field(default_factory=set)
    unique_dests: set[str] = field(default_factory=set)
    module_loads: int = 0
    rwx_events: int = 0
    last_seen_ns: int = 0


class EventClassifier:
    """Sits on a :class:`TraceEventBus` and classifies events live."""

    def __init__(
        self,
        context: "AnalysisContext | None",
        ruleset: Ruleset,
        *,
        source_bus: TraceEventBus,
        anomaly_window_s: float = 30.0,
    ) -> None:
        self._context = context
        self._ruleset = ruleset
        self._source_bus = source_bus
        self._classified_bus = TraceEventBus()
        self._subscription: EventSubscription | None = None
        self._task: asyncio.Task | None = None
        self._running = False
        self._lock = threading.Lock()
        self._windows: dict[int, _PidWindow] = {}
        self._anomaly_window_s = anomaly_window_s

    @property
    def bus(self) -> TraceEventBus:
        """The classifier's outbound bus (decorated events)."""
        return self._classified_bus

    @property
    def running(self) -> bool:
        return self._running

    async def start(self) -> None:
        if self._running:
            return
        self._subscription = self._source_bus.subscribe()
        self._running = True
        self._task = asyncio.create_task(self._run())
        log.info("classifier_started", rules=len(self._ruleset))

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self._subscription is not None:
            self._source_bus.unsubscribe(self._subscription)
            self._subscription = None
        log.info("classifier_stopped")

    async def _run(self) -> None:
        assert self._subscription is not None
        while self._running:
            event = await self._subscription.get(timeout=0.5)
            if event is None:
                continue
            try:
                self.classify_and_publish(event)
            except Exception as e:  # noqa: BLE001
                log.warning("classify_event_error", error=str(e))

    # ------------------------------------------------------------------
    # Sync entrypoint (used by replay + tests)
    # ------------------------------------------------------------------

    def classify_and_publish(self, event: MonitorEvent) -> list[ClassificationResult]:
        """Classify *event* in place and publish it onto the classified bus.

        Returns the list of matches so callers (tests, the replayer)
        can inspect them directly. Safe to call from either async or
        sync contexts.
        """
        self._update_window(event)
        results = self._ruleset.classify(event)
        anomaly = self._maybe_score_anomaly(event)
        if anomaly >= 0.6:
            results.append(
                ClassificationResult(
                    rule_id="anomaly.score",
                    title="Anomaly score elevated",
                    severity="warning" if anomaly < 0.8 else "critical",
                    category="anomaly",
                    labels={"score": f"{anomaly:.2f}"},
                    anomaly_score=anomaly,
                )
            )

        if results:
            # Attach to the event and bump severity to the worst match.
            event.metadata["classifications"] = [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "severity": r.severity,
                    "category": r.category,
                    "attack_ids": list(r.attack_ids),
                    "labels": dict(r.labels),
                    "anomaly_score": r.anomaly_score,
                }
                for r in results
            ]
            worst = max(results, key=lambda r: self._ruleset.severity_rank(r.severity))
            event.severity = _severity_enum(worst.severity)
            # Publish a typed event into the core bus for each result.
            if self._context is not None:
                for r in results:
                    self._context.events.publish(
                        EventClassifiedEvent(
                            source_event=event,
                            rule_id=r.rule_id,
                            severity=r.severity,
                            labels=r.labels,
                            attack_ids=r.attack_ids,
                            title=r.title,
                        )
                    )

        self._classified_bus.publish_sync(event)
        return results

    def snapshot_window(self, pid: int) -> _PidWindow | None:
        with self._lock:
            return self._windows.get(pid)

    # ------------------------------------------------------------------
    # Anomaly bridge
    # ------------------------------------------------------------------

    def _update_window(self, event: MonitorEvent) -> None:
        pid = event.process.pid if event.process else 0
        if pid <= 0:
            return
        now_ns = event.wall_clock_ns or time.time_ns()
        cutoff = now_ns - int(self._anomaly_window_s * 1_000_000_000)
        with self._lock:
            win = self._windows.get(pid)
            if win is None:
                win = _PidWindow(last_seen_ns=now_ns)
                self._windows[pid] = win
            win.last_seen_ns = now_ns
            win.syscalls += 1
            if event.category == EventCategory.FILE_IO:
                path = event.args.get("path") or event.args.get("filename")
                if isinstance(path, str):
                    win.unique_paths.add(path)
            elif event.category == EventCategory.NETWORK:
                dest = event.args.get("dest") or event.args.get("remote")
                if isinstance(dest, str):
                    win.unique_dests.add(dest)
            elif event.category == EventCategory.MODULE:
                win.module_loads += 1
            elif event.category == EventCategory.MEMORY:
                if event.args.get("prot") == "rwx":
                    win.rwx_events += 1
            # Prune old windows.
            stale = [p for p, w in self._windows.items() if w.last_seen_ns < cutoff]
            for p in stale:
                del self._windows[p]

    def _maybe_score_anomaly(self, event: MonitorEvent) -> float:
        """Forward a feature vector to the existing anomaly scorer.

        We map live aggregate state onto the feature names the static
        :class:`deepview.detection.anomaly.AnomalyDetector` expects so
        the heuristic (and optional IsolationForest) keep doing what
        they already do without duplicating the logic.
        """
        pid = event.process.pid if event.process else 0
        if pid <= 0:
            return 0.0
        win = self._windows.get(pid)
        if win is None:
            return 0.0
        features = {
            "vad_count": win.syscalls,
            "rwx_vad_count": win.rwx_events,
            "module_count": win.module_loads,
            "heap_entropy": min(1.0, len(win.unique_paths) / 500.0),
            "handle_count": len(win.unique_paths) + len(win.unique_dests),
        }
        try:
            from deepview.detection.anomaly import AnomalyDetector
        except Exception:  # noqa: BLE001
            return 0.0
        try:
            detector = AnomalyDetector()
            result = detector.score_process(features)
            return float(getattr(result, "score", 0.0))
        except Exception:  # noqa: BLE001
            return 0.0


def _severity_enum(severity: str) -> EventSeverity:
    return {
        "info": EventSeverity.INFO,
        "warning": EventSeverity.WARNING,
        "critical": EventSeverity.CRITICAL,
    }.get(severity.lower(), EventSeverity.INFO)
