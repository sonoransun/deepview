"""Causal chain builder — walks the correlation graph to produce
human-readable incident narratives.

Input: a :class:`CorrelationGraph`. Output: a list of :class:`CausalChain`
objects that collapse multi-step attacker activity into single rows on the
unified timeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from deepview.core.correlation.entity import EntityKind, ForensicEntity
from deepview.core.correlation.graph import CorrelationGraph, Edge, RelationType


@dataclass
class CausalChain:
    """A linear causal chain of forensic events.

    ``steps`` is ordered from root cause to observed effect. Each step is a
    tuple ``(entity_id, relation, target_id, timestamp_ns)`` so the caller
    can render the chain however they like (timeline row, report section,
    subgraph export).
    """

    root: str
    tail: str
    description: str
    steps: list[tuple[str, RelationType, str, int]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = [self.steps[0][0] if self.steps else self.root]
        for _, relation, dst, _ in self.steps:
            parts.append(f"-[{relation.value}]->")
            parts.append(dst)
        return " ".join(parts)


class CausalityBuilder:
    """Produces :class:`CausalChain` objects from a :class:`CorrelationGraph`."""

    def __init__(self, graph: CorrelationGraph, *, max_depth: int = 6) -> None:
        self.graph = graph
        self.max_depth = max_depth

    def chains(self) -> list[CausalChain]:
        """Extract interesting chains (starting from root processes)."""
        chains: list[CausalChain] = []
        roots = [
            e
            for e in self.graph.entities(EntityKind.PROCESS)
            if not self.graph.incoming(e.entity_id, RelationType.SPAWNED)
        ]
        for root in roots:
            chains.extend(self._chains_from(root.entity_id))
        # Also start from persistence nodes — they're terminal events worth
        # unrolling backwards.
        for persist in self.graph.entities(EntityKind.PERSISTENCE):
            chains.extend(self._chains_to(persist.entity_id))
        return chains

    def _chains_from(self, start: str) -> list[CausalChain]:
        """Forward walk: find chains starting at ``start``."""
        results: list[CausalChain] = []
        stack: list[tuple[str, list[tuple[str, RelationType, str, int]]]] = [(start, [])]
        while stack:
            node_id, path = stack.pop()
            if len(path) >= self.max_depth:
                if path:
                    results.append(self._build_chain(start, node_id, path))
                continue
            outgoing = self.graph.outgoing(node_id)
            if not outgoing:
                if path:
                    results.append(self._build_chain(start, node_id, path))
                continue
            for edge in outgoing:
                if any(step[2] == edge.dst for step in path):
                    continue  # skip cycles
                new_path = path + [(edge.src, edge.relation, edge.dst, edge.timestamp_ns)]
                stack.append((edge.dst, new_path))
        return results

    def _chains_to(self, target: str) -> list[CausalChain]:
        """Backward walk: find chains that terminate at ``target``."""
        results: list[CausalChain] = []
        stack: list[tuple[str, list[tuple[str, RelationType, str, int]]]] = [(target, [])]
        while stack:
            node_id, path = stack.pop()
            if len(path) >= self.max_depth:
                continue
            incoming = self.graph.incoming(node_id)
            if not incoming:
                if path:
                    root = path[0][0]
                    results.append(self._build_chain(root, target, list(reversed(path))))
                continue
            for edge in incoming:
                if any(step[0] == edge.src for step in path):
                    continue
                new_path = path + [(edge.src, edge.relation, edge.dst, edge.timestamp_ns)]
                stack.append((edge.src, new_path))
        return results

    def _build_chain(
        self,
        root: str,
        tail: str,
        steps: list[tuple[str, RelationType, str, int]],
    ) -> CausalChain:
        description = " -> ".join(step[2] for step in steps[:4])
        mitre: set[str] = set()
        for src_id, _, dst_id, _ in steps:
            for entity_id in (src_id, dst_id):
                if not self.graph.has_entity(entity_id):
                    continue
                entity = self.graph.get_entity(entity_id)
                m = entity.attributes.get("mitre_technique", "")
                if m:
                    mitre.add(str(m))
        return CausalChain(
            root=root,
            tail=tail,
            description=description,
            steps=steps,
            mitre_techniques=sorted(mitre),
        )
