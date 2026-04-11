"""Cross-subsystem forensic correlation.

The correlator glues together findings from memory analysis, live tracing,
instrumentation, persistence scans, and pattern scans into a single
``CorrelationGraph``. Rules walk the graph to promote raw signals into
``CompositeFinding`` objects mapped to MITRE ATT&CK techniques.
"""
from __future__ import annotations

from deepview.core.correlation.composite_events import (
    CompositeFinding,
    CompositeFindingEvent,
    FindingSeverity,
)
from deepview.core.correlation.engine import CorrelationEngine
from deepview.core.correlation.entity import (
    CredentialEntity,
    EntityKind,
    FileEntity,
    ForensicEntity,
    HostEntity,
    MemoryRegionEntity,
    ModuleEntity,
    NetworkFlowEntity,
    PersistenceEntity,
    ProcessEntity,
)
from deepview.core.correlation.graph import CorrelationGraph, Edge, RelationType
from deepview.core.correlation.rules import (
    CorrelationRule,
    DEFAULT_RULES,
    RuleContext,
)

__all__ = [
    "CompositeFinding",
    "CompositeFindingEvent",
    "CorrelationEngine",
    "CorrelationGraph",
    "CorrelationRule",
    "CredentialEntity",
    "DEFAULT_RULES",
    "Edge",
    "EntityKind",
    "FileEntity",
    "FindingSeverity",
    "ForensicEntity",
    "HostEntity",
    "MemoryRegionEntity",
    "ModuleEntity",
    "NetworkFlowEntity",
    "PersistenceEntity",
    "ProcessEntity",
    "RelationType",
    "RuleContext",
]
