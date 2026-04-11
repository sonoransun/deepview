"""Composite findings emitted by the correlation engine."""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field

from deepview.core.events import Event


class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CompositeFinding:
    """A multi-entity finding produced by a correlation rule.

    Captures a subgraph (list of entity IDs + edges) plus MITRE mapping and
    human-readable description. Downstream (reporting, timeline) can walk back
    into the graph via the entity IDs.
    """

    name: str
    rule_id: str
    description: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    mitre_techniques: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    edge_sigs: list[tuple[str, str, str]] = field(default_factory=list)
    timestamp_ns: int = 0
    evidence: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp_ns == 0:
            self.timestamp_ns = time.time_ns()


class CompositeFindingEvent(Event):
    """Event-bus message wrapping a :class:`CompositeFinding`."""

    def __init__(self, finding: CompositeFinding) -> None:
        self.finding = finding

    @property
    def name(self) -> str:
        return self.finding.name

    @property
    def severity(self) -> FindingSeverity:
        return self.finding.severity
