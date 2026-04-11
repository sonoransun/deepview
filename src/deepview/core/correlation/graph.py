"""In-memory correlation graph.

Intentionally dependency-free (no networkx) so the core stays lightweight.
The structure is a labelled multi-digraph: each edge has a ``RelationType``,
and multiple edges with different relations may connect the same pair.
"""
from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from deepview.core.correlation.entity import EntityKind, ForensicEntity
from deepview.core.exceptions import EntityNotFoundError


class RelationType(str, enum.Enum):
    SPAWNED = "spawned"
    OPENED = "opened"
    WROTE = "wrote"
    READ = "read"
    MAPPED = "mapped"
    HOOKED = "hooked"
    CONNECTED_TO = "connected_to"
    LISTENED_ON = "listened_on"
    AUTHENTICATED_AS = "authenticated_as"
    READ_CREDENTIAL = "read_credential"
    INJECTED_INTO = "injected_into"
    MODIFIED = "modified"
    PERSISTED_AS = "persisted_as"
    LOADED = "loaded"
    CONTAINS = "contains"
    CHILD_OF = "child_of"
    FOUND_BY = "found_by"


@dataclass
class Edge:
    src: str
    dst: str
    relation: RelationType
    timestamp_ns: int = 0
    source_event_id: str = ""
    attributes: dict[str, object] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.dst, self.relation.value)


class CorrelationGraph:
    """Thread-safe labelled multi-digraph of forensic entities.

    Merging two graphs (``CorrelationGraph.merge``) lets a live-trace graph be
    combined with a post-hoc memory-analysis graph of the same host: matching
    entity IDs unify into single nodes with attribute-merged content.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, ForensicEntity] = {}
        self._edges: list[Edge] = []
        self._out: dict[str, list[int]] = {}
        self._in: dict[str, list[int]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    def add_entity(self, entity: ForensicEntity) -> ForensicEntity:
        """Insert a new entity or merge into an existing one with the same id.

        Returns the resulting entity (possibly the existing one).
        """
        with self._lock:
            existing = self._nodes.get(entity.entity_id)
            if existing is None:
                self._nodes[entity.entity_id] = entity
                self._out.setdefault(entity.entity_id, [])
                self._in.setdefault(entity.entity_id, [])
                return entity
            # Merge: keep existing, fold new labels/attributes in
            existing.labels |= entity.labels
            existing.merge_attributes(entity.attributes)
            existing.observe(entity.first_seen_ns)
            existing.observe(entity.last_seen_ns)
            return existing

    def get_entity(self, entity_id: str) -> ForensicEntity:
        try:
            return self._nodes[entity_id]
        except KeyError as exc:
            raise EntityNotFoundError(entity_id) from exc

    def has_entity(self, entity_id: str) -> bool:
        return entity_id in self._nodes

    def entities(self, kind: EntityKind | None = None) -> list[ForensicEntity]:
        with self._lock:
            if kind is None:
                return list(self._nodes.values())
            return [e for e in self._nodes.values() if e.kind == kind]

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------

    def add_edge(
        self,
        src: str,
        dst: str,
        relation: RelationType,
        timestamp_ns: int = 0,
        source_event_id: str = "",
        attributes: dict[str, object] | None = None,
    ) -> Edge:
        """Add a typed edge. Both endpoints must already be in the graph."""
        with self._lock:
            if src not in self._nodes:
                raise EntityNotFoundError(src)
            if dst not in self._nodes:
                raise EntityNotFoundError(dst)
            edge = Edge(
                src=src,
                dst=dst,
                relation=relation,
                timestamp_ns=timestamp_ns,
                source_event_id=source_event_id,
                attributes=dict(attributes or {}),
            )
            idx = len(self._edges)
            self._edges.append(edge)
            self._out.setdefault(src, []).append(idx)
            self._in.setdefault(dst, []).append(idx)
            return edge

    def edges(self) -> list[Edge]:
        with self._lock:
            return list(self._edges)

    def outgoing(
        self, entity_id: str, relation: RelationType | None = None
    ) -> list[Edge]:
        with self._lock:
            idxs = self._out.get(entity_id, [])
            if relation is None:
                return [self._edges[i] for i in idxs]
            return [self._edges[i] for i in idxs if self._edges[i].relation == relation]

    def incoming(
        self, entity_id: str, relation: RelationType | None = None
    ) -> list[Edge]:
        with self._lock:
            idxs = self._in.get(entity_id, [])
            if relation is None:
                return [self._edges[i] for i in idxs]
            return [self._edges[i] for i in idxs if self._edges[i].relation == relation]

    # ------------------------------------------------------------------
    # Walks
    # ------------------------------------------------------------------

    def walk_from(
        self,
        start: str,
        relations: Iterable[RelationType] | None = None,
        max_depth: int = 5,
        predicate: Callable[[ForensicEntity], bool] | None = None,
    ) -> Iterator[ForensicEntity]:
        """BFS walk from ``start``, yielding entities that match ``predicate``.

        ``relations`` restricts which edge types may be traversed. Cycle-safe.
        """
        if start not in self._nodes:
            return
        allowed = set(relations) if relations else None
        visited: set[str] = {start}
        frontier: list[tuple[str, int]] = [(start, 0)]
        while frontier:
            node_id, depth = frontier.pop(0)
            if depth > max_depth:
                continue
            entity = self._nodes[node_id]
            if predicate is None or predicate(entity):
                yield entity
            if depth == max_depth:
                continue
            for edge in self.outgoing(node_id):
                if allowed is not None and edge.relation not in allowed:
                    continue
                if edge.dst in visited:
                    continue
                visited.add(edge.dst)
                frontier.append((edge.dst, depth + 1))

    def descendants(self, start: str, relation: RelationType) -> list[ForensicEntity]:
        return list(
            self.walk_from(start, relations=[relation], max_depth=16, predicate=None)
        )[1:]  # skip the start node itself

    # ------------------------------------------------------------------
    # Merging
    # ------------------------------------------------------------------

    def merge(self, other: CorrelationGraph) -> None:
        """Merge ``other`` into this graph in place (idempotent)."""
        if other is self:
            return
        with self._lock:
            for entity in other.entities():
                self.add_entity(entity.model_copy(deep=True))
            seen: set[tuple[str, str, str, int]] = set()
            # Deduplicate by (src, dst, relation, timestamp_ns)
            for edge in other.edges():
                sig = (edge.src, edge.dst, edge.relation.value, edge.timestamp_ns)
                if sig in seen:
                    continue
                seen.add(sig)
                # Skip if we already have an identical edge locally
                dup = False
                for existing in self.outgoing(edge.src, edge.relation):
                    if (
                        existing.dst == edge.dst
                        and existing.timestamp_ns == edge.timestamp_ns
                    ):
                        dup = True
                        break
                if dup:
                    continue
                self.add_edge(
                    edge.src,
                    edge.dst,
                    edge.relation,
                    timestamp_ns=edge.timestamp_ns,
                    source_event_id=edge.source_event_id,
                    attributes=dict(edge.attributes),
                )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def size(self) -> tuple[int, int]:
        """Return ``(node_count, edge_count)``."""
        with self._lock:
            return len(self._nodes), len(self._edges)

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._out.clear()
            self._in.clear()
