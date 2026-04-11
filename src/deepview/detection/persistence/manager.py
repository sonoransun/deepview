"""Persistence orchestration — picks the right detectors and pipes findings
into the correlation graph."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from deepview.core.logging import get_logger
from deepview.core.types import Platform
from deepview.detection.persistence.base import (
    PersistenceArtifact,
    PersistenceDetector,
    PersistenceSeverity,
)
from deepview.detection.persistence.containers import ContainerPersistenceDetector
from deepview.detection.persistence.linux import LinuxPersistenceDetector
from deepview.detection.persistence.macos import MacOSPersistenceDetector
from deepview.detection.persistence.windows import WindowsPersistenceDetector

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext


log = get_logger("detection.persistence.manager")


class PersistenceManager:
    """Picks detectors based on ``PlatformInfo`` and runs them.

    Typical usage::

        mgr = PersistenceManager(context)
        findings = mgr.scan()

    Findings are automatically added to the correlation graph so the
    ``PERSISTENCE_NEW_UNIT`` rule (see ``correlation.rules``) can fire on
    anything that differs from the host's stored baseline.
    """

    def __init__(
        self,
        context: "AnalysisContext | None" = None,
        *,
        linux_root: Path | str = "/",
        macos_root: Path | str = "/",
        manifest_roots: Iterable[Path | str] | None = None,
    ) -> None:
        self.context = context
        self._linux = LinuxPersistenceDetector(root=linux_root)
        self._macos = MacOSPersistenceDetector(root=macos_root)
        self._windows = WindowsPersistenceDetector()
        self._containers = ContainerPersistenceDetector(
            manifest_roots=[Path(p) for p in (manifest_roots or [])]
        )

    def detectors_for_current_host(self) -> list[PersistenceDetector]:
        """Return the detectors appropriate for the current platform."""
        detectors: list[PersistenceDetector] = []
        if self.context is None:
            detectors.extend([self._linux, self._macos, self._windows])
        else:
            os = self.context.platform.os
            if os is Platform.LINUX:
                detectors.append(self._linux)
            elif os is Platform.MACOS:
                detectors.append(self._macos)
            elif os is Platform.WINDOWS:
                detectors.append(self._windows)
        if self._containers.manifest_roots:
            detectors.append(self._containers)
        return detectors

    def scan(
        self,
        *,
        include_user_scope: bool = True,
        baseline_fingerprints: set[str] | None = None,
        feed_correlation: bool = True,
    ) -> list[PersistenceArtifact]:
        """Scan for persistence and (optionally) update the correlation graph.

        ``baseline_fingerprints`` is an optional set of known-good
        fingerprints; any finding whose fingerprint is *not* in this set is
        marked ``deviation_from_baseline=True``.
        """
        all_findings: list[PersistenceArtifact] = []
        for detector in self.detectors_for_current_host():
            try:
                produced = detector.scan(include_user_scope=include_user_scope)
            except Exception:
                log.exception("persistence_detector_failed", detector=detector.platform)
                continue
            for finding in produced:
                if baseline_fingerprints is not None:
                    finding.deviation_from_baseline = finding.fingerprint() not in baseline_fingerprints
            all_findings.extend(produced)
        if feed_correlation and self.context is not None:
            self._feed_correlator(all_findings)
        return all_findings

    # ------------------------------------------------------------------

    def _feed_correlator(self, findings: list[PersistenceArtifact]) -> None:
        if self.context is None:
            return
        correlator = self.context.correlation  # lazy-created if absent
        for f in findings:
            correlator.record_persistence(
                mechanism=f.mechanism,
                location=f.location,
                mitre_technique=f.mitre_technique,
                deviation_from_baseline=f.deviation_from_baseline,
                attributes={
                    "severity": f.severity.value,
                    "description": f.description,
                    "command": f.command,
                    "suspicious_reasons": list(f.suspicious_reasons),
                    "fingerprint": f.fingerprint(),
                    "owning_user": f.owning_user,
                },
            )
