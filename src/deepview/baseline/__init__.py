"""Baseline / differential analysis engine.

Takes repeated ``HostSnapshot`` samples, stores them efficiently in
SQLite, and computes deltas that finally give
:class:`deepview.core.events.BaselineDeviationEvent` and
:class:`deepview.core.events.MemoryDiffEvent` concrete publishers.
"""
from __future__ import annotations

from deepview.baseline.differ import (
    FilesystemDelta,
    MemoryPageDelta,
    ModuleDelta,
    NetworkDelta,
    PersistenceDelta,
    ProcessDelta,
    SnapshotDelta,
    SnapshotDiffer,
)
from deepview.baseline.publisher import DeviationPublisher
from deepview.baseline.rules import BaselineRule, DEFAULT_BASELINE_RULES
from deepview.baseline.snapshot import HostSnapshot, ModuleSample, NetworkSample, ProcessSample
from deepview.baseline.store import SnapshotStore

__all__ = [
    "BaselineRule",
    "DEFAULT_BASELINE_RULES",
    "DeviationPublisher",
    "FilesystemDelta",
    "HostSnapshot",
    "MemoryPageDelta",
    "ModuleDelta",
    "ModuleSample",
    "NetworkDelta",
    "NetworkSample",
    "PersistenceDelta",
    "ProcessDelta",
    "ProcessSample",
    "SnapshotDelta",
    "SnapshotDiffer",
    "SnapshotStore",
]
