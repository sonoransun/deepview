"""The correlation engine wires events and findings into the graph.

The engine is deliberately **stateless between events** other than the graph
itself — rules are pure functions over (event, graph). This makes it trivial
to re-run rules after a graph merge, and means live-trace and post-hoc
analyses compose cleanly.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

from deepview.core.correlation.composite_events import (
    CompositeFinding,
    CompositeFindingEvent,
)
from deepview.core.correlation.entity import (
    EntityKind,
    FileEntity,
    ForensicEntity,
    ModuleEntity,
    NetworkFlowEntity,
    PersistenceEntity,
    ProcessEntity,
)
from deepview.core.correlation.graph import CorrelationGraph, RelationType
from deepview.core.correlation.rules import CorrelationRule, DEFAULT_RULES, RuleContext
from deepview.core.events import EventBus
from deepview.core.logging import get_logger
from deepview.core.types import ProcessContext

log = get_logger("correlation.engine")


FindingListener = Callable[[CompositeFinding], None]


class CorrelationEngine:
    """Aggregates cross-subsystem forensic state into a ``CorrelationGraph``.

    Usage:

        engine = CorrelationEngine(event_bus=ctx.events)
        engine.register_default_rules()
        engine.record_process(process_ctx)
        engine.record_file_access(process_ctx, path="/etc/shadow")
        for finding in engine.run_rules():
            ...
    """

    def __init__(
        self,
        event_bus: EventBus | None = None,
        graph: CorrelationGraph | None = None,
    ) -> None:
        self.graph = graph or CorrelationGraph()
        self.rules: list[CorrelationRule] = []
        self._event_bus = event_bus
        self._findings: list[CompositeFinding] = []
        self._listeners: list[FindingListener] = []
        self._lock = threading.RLock()
        self._fingerprints: set[str] = set()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def register_rule(self, rule: CorrelationRule) -> None:
        with self._lock:
            self.rules.append(rule)

    def register_default_rules(self) -> None:
        for rule in DEFAULT_RULES:
            self.register_rule(rule)

    def on_finding(self, listener: FindingListener) -> None:
        with self._lock:
            self._listeners.append(listener)

    # ------------------------------------------------------------------
    # Recording helpers — subsystems call these to add state
    # ------------------------------------------------------------------

    def record_process(
        self,
        ctx: ProcessContext,
        *,
        boot_ns: int | None = None,
        timestamp_ns: int = 0,
    ) -> ProcessEntity:
        entity = ProcessEntity.from_context(ctx, boot_ns)
        entity.observe(timestamp_ns)
        # Thread start addresses are used by RWXInjectionRule
        if ctx.threads:
            entity.attributes["thread_start_addrs"] = [
                t.start_address for t in ctx.threads if t.start_address
            ]
        entity.attributes.setdefault("pid", ctx.pid)
        entity.attributes.setdefault("comm", ctx.comm)
        merged = self.graph.add_entity(entity)
        assert isinstance(merged, ProcessEntity)
        # Modules → ModuleEntity + LOADED edge
        for mod in ctx.loaded_modules:
            module_entity = ModuleEntity.from_module(mod.name, mod.path, mod.base_address)
            module_entity.observe(timestamp_ns)
            self.graph.add_entity(module_entity)
            self._safe_edge(
                merged.entity_id,
                module_entity.entity_id,
                RelationType.LOADED,
                timestamp_ns=timestamp_ns,
            )
        # Parent chain → CHILD_OF edges
        if ctx.ppid:
            parent_id = f"process:{ctx.ppid}"
            if boot_ns is not None:
                parent_id = f"process:{ctx.ppid}@{boot_ns}"
            if not self.graph.has_entity(parent_id):
                parent_entity = ProcessEntity(
                    entity_id=parent_id,
                    pid=ctx.ppid,
                )
                parent_entity.observe(timestamp_ns)
                self.graph.add_entity(parent_entity)
            self._safe_edge(
                merged.entity_id,
                parent_id,
                RelationType.CHILD_OF,
                timestamp_ns=timestamp_ns,
            )
            self._safe_edge(
                parent_id,
                merged.entity_id,
                RelationType.SPAWNED,
                timestamp_ns=timestamp_ns,
            )
        return merged

    def record_file_access(
        self,
        process: ProcessContext | ProcessEntity,
        path: str,
        *,
        relation: RelationType = RelationType.OPENED,
        timestamp_ns: int = 0,
        inode: int = 0,
        device: str = "",
        sha256: str = "",
        labels: set[str] | None = None,
        source_event_id: str = "",
    ) -> FileEntity:
        proc_entity = self._ensure_process(process)
        file_entity = FileEntity.from_path(
            path, inode=inode, device=device, sha256=sha256
        )
        file_entity.observe(timestamp_ns)
        if labels:
            file_entity.labels |= labels
        file_entity.attributes["path"] = path
        merged_file = self.graph.add_entity(file_entity)
        self._safe_edge(
            proc_entity.entity_id,
            merged_file.entity_id,
            relation,
            timestamp_ns=timestamp_ns,
            source_event_id=source_event_id,
        )
        return merged_file  # type: ignore[return-value]

    def record_network_flow(
        self,
        process: ProcessContext | ProcessEntity,
        *,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        timestamp_ns: int = 0,
        source_event_id: str = "",
    ) -> NetworkFlowEntity:
        proc_entity = self._ensure_process(process)
        flow = NetworkFlowEntity.from_tuple(
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            start_ns=timestamp_ns,
        )
        merged = self.graph.add_entity(flow)
        self._safe_edge(
            proc_entity.entity_id,
            merged.entity_id,
            RelationType.CONNECTED_TO,
            timestamp_ns=timestamp_ns,
            source_event_id=source_event_id,
        )
        return merged  # type: ignore[return-value]

    def record_memory_region(
        self,
        process: ProcessContext | ProcessEntity,
        *,
        start: int,
        end: int,
        protection: str = "",
        timestamp_ns: int = 0,
    ) -> ForensicEntity:
        from deepview.core.correlation.entity import MemoryRegionEntity

        proc_entity = self._ensure_process(process)
        region = MemoryRegionEntity.from_region(
            pid=getattr(proc_entity, "pid", 0),
            start=start,
            end=end,
            protection=protection,
        )
        region.observe(timestamp_ns)
        region.attributes.update({"start": start, "end": end, "protection": protection})
        merged = self.graph.add_entity(region)
        self._safe_edge(
            proc_entity.entity_id,
            merged.entity_id,
            RelationType.MAPPED,
            timestamp_ns=timestamp_ns,
        )
        return merged

    def record_injection(
        self,
        attacker: ProcessContext | ProcessEntity,
        victim: ProcessContext | ProcessEntity,
        *,
        timestamp_ns: int = 0,
    ) -> None:
        a = self._ensure_process(attacker)
        v = self._ensure_process(victim)
        self._safe_edge(a.entity_id, v.entity_id, RelationType.INJECTED_INTO, timestamp_ns)

    def record_persistence(
        self,
        *,
        mechanism: str,
        location: str,
        mitre_technique: str = "",
        owning_process: ProcessContext | ProcessEntity | None = None,
        deviation_from_baseline: bool = False,
        attributes: dict[str, Any] | None = None,
        timestamp_ns: int = 0,
    ) -> PersistenceEntity:
        entity = PersistenceEntity.make(
            mechanism=mechanism,
            location=location,
            mitre_technique=mitre_technique,
        )
        entity.observe(timestamp_ns)
        entity.attributes.update(attributes or {})
        entity.attributes["deviation_from_baseline"] = deviation_from_baseline
        if mitre_technique:
            entity.attributes["mitre_technique"] = mitre_technique
        merged = self.graph.add_entity(entity)
        assert isinstance(merged, PersistenceEntity)
        if owning_process is not None:
            proc_entity = self._ensure_process(owning_process)
            self._safe_edge(
                proc_entity.entity_id,
                merged.entity_id,
                RelationType.PERSISTED_AS,
                timestamp_ns=timestamp_ns,
            )
        return merged

    def add_finding_entity(
        self,
        parent: ProcessEntity | None,
        *,
        finding_name: str,
        finding_id: str,
        severity: str = "",
        description: str = "",
        mitre: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> ForensicEntity:
        """Attach a detector finding as a first-class entity in the graph."""
        entity = ForensicEntity(
            entity_id=f"finding:{finding_id}",
            kind=EntityKind.FINDING,
            labels={finding_name.lower()},
            attributes={
                "name": finding_name,
                "severity": severity,
                "description": description,
                "mitre": mitre,
                "evidence": dict(evidence or {}),
            },
        )
        merged = self.graph.add_entity(entity)
        if parent is not None:
            self._safe_edge(parent.entity_id, merged.entity_id, RelationType.FOUND_BY)
        return merged

    # ------------------------------------------------------------------
    # Rule execution
    # ------------------------------------------------------------------

    def run_rules(self, triggering_event: Any = None) -> list[CompositeFinding]:
        """Run every registered rule, dedup findings, return new ones."""
        ctx = RuleContext(graph=self.graph, event=triggering_event)
        new_findings: list[CompositeFinding] = []
        with self._lock:
            rules_snapshot = list(self.rules)
        for rule in rules_snapshot:
            try:
                produced = rule.match(ctx)
            except Exception:  # pragma: no cover — a faulty rule should not blow up tracing
                log.exception("rule_error", rule=rule.rule_id or rule.__class__.__name__)
                continue
            for finding in produced:
                fp = _finding_fingerprint(finding)
                with self._lock:
                    if fp in self._fingerprints:
                        continue
                    self._fingerprints.add(fp)
                    self._findings.append(finding)
                new_findings.append(finding)
        for finding in new_findings:
            self._dispatch_finding(finding)
        return new_findings

    @property
    def findings(self) -> list[CompositeFinding]:
        with self._lock:
            return list(self._findings)

    # ------------------------------------------------------------------
    # Graph merging
    # ------------------------------------------------------------------

    def merge_graph(self, other: CorrelationGraph) -> None:
        self.graph.merge(other)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_process(
        self, process: ProcessContext | ProcessEntity
    ) -> ProcessEntity:
        if isinstance(process, ProcessEntity):
            if self.graph.has_entity(process.entity_id):
                existing = self.graph.get_entity(process.entity_id)
                assert isinstance(existing, ProcessEntity)
                return existing
            merged = self.graph.add_entity(process)
            assert isinstance(merged, ProcessEntity)
            return merged
        return self.record_process(process)

    def _safe_edge(
        self,
        src: str,
        dst: str,
        relation: RelationType,
        timestamp_ns: int = 0,
        source_event_id: str = "",
    ) -> None:
        try:
            self.graph.add_edge(
                src, dst, relation, timestamp_ns=timestamp_ns, source_event_id=source_event_id
            )
        except Exception:  # pragma: no cover
            log.debug("edge_add_failed", src=src, dst=dst, relation=relation.value)

    def _dispatch_finding(self, finding: CompositeFinding) -> None:
        for listener in list(self._listeners):
            try:
                listener(finding)
            except Exception:  # pragma: no cover
                log.exception("finding_listener_failed")
        if self._event_bus is not None:
            try:
                self._event_bus.publish(CompositeFindingEvent(finding))
            except Exception:  # pragma: no cover
                log.exception("composite_event_publish_failed")


def _finding_fingerprint(finding: CompositeFinding) -> str:
    parts = [finding.rule_id, "|".join(sorted(finding.entity_ids)), finding.description]
    return "::".join(parts)
