"""Persistence detection — cross-platform collectors that enumerate known
mechanisms used by attackers to survive reboots or re-establish footholds.

The module covers MITRE ATT&CK tactic TA0003 (Persistence) with broad but
shallow coverage across Linux, Windows, macOS, and container runtimes.
Each detector returns a list of :class:`PersistenceArtifact` records;
the :class:`PersistenceManager` orchestrates platform selection and feeds
findings into the correlation graph.
"""
from __future__ import annotations

from deepview.detection.persistence.base import (
    PersistenceArtifact,
    PersistenceDetector,
    PersistenceSeverity,
)
from deepview.detection.persistence.containers import ContainerPersistenceDetector
from deepview.detection.persistence.linux import LinuxPersistenceDetector
from deepview.detection.persistence.macos import MacOSPersistenceDetector
from deepview.detection.persistence.manager import PersistenceManager
from deepview.detection.persistence.windows import WindowsPersistenceDetector

__all__ = [
    "ContainerPersistenceDetector",
    "LinuxPersistenceDetector",
    "MacOSPersistenceDetector",
    "PersistenceArtifact",
    "PersistenceDetector",
    "PersistenceManager",
    "PersistenceSeverity",
    "WindowsPersistenceDetector",
]
