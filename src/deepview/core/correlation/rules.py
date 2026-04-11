"""Correlation rule base + built-in rule set.

Rules inspect the graph (and the triggering event) and produce
:class:`CompositeFinding` objects when a pattern matches. Rules are kept
deliberately simple — complex graph queries are expressed as Python on the
lightweight :class:`CorrelationGraph`, not via a dedicated DSL.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from deepview.core.correlation.composite_events import CompositeFinding, FindingSeverity
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


@dataclass
class RuleContext:
    """State passed to each rule invocation."""

    graph: CorrelationGraph
    event: Any = None
    now_ns: int = 0

    def __post_init__(self) -> None:
        if self.now_ns == 0:
            self.now_ns = time.time_ns()


class CorrelationRule(ABC):
    """Base correlation rule.

    Subclasses implement :meth:`match` which should return a list of new
    findings (possibly empty). The engine enforces per-rule dedup via
    ``fingerprint``.
    """

    rule_id: str = ""
    name: str = ""
    description: str = ""
    mitre_techniques: tuple[str, ...] = ()
    severity: FindingSeverity = FindingSeverity.MEDIUM

    @abstractmethod
    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        ...

    def finding(
        self,
        description: str,
        entity_ids: list[str],
        *,
        timestamp_ns: int = 0,
        evidence: dict[str, object] | None = None,
        severity: FindingSeverity | None = None,
    ) -> CompositeFinding:
        return CompositeFinding(
            name=self.name or self.__class__.__name__,
            rule_id=self.rule_id or self.__class__.__name__,
            description=description,
            severity=severity or self.severity,
            mitre_techniques=list(self.mitre_techniques),
            entity_ids=list(entity_ids),
            timestamp_ns=timestamp_ns,
            evidence=evidence or {},
        )


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------


class RWXInjectionRule(CorrelationRule):
    """Process owns an RWX memory region *and* a thread starting inside it."""

    rule_id = "INJECTION_RWX_THREAD"
    name = "RWX region with thread start inside"
    description = (
        "A process has a writable + executable memory region that is the target "
        "of a thread start address — classic in-memory shellcode injection."
    )
    mitre_techniques = ("T1055",)
    severity = FindingSeverity.HIGH

    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for process in ctx.graph.entities(EntityKind.PROCESS):
            rwx_regions = [
                r
                for r in ctx.graph.descendants(process.entity_id, RelationType.MAPPED)
                if r.kind == EntityKind.MEMORY_REGION
                and "X" in str(r.attributes.get("protection", "")).upper()
                and "W" in str(r.attributes.get("protection", "")).upper()
            ]
            if not rwx_regions:
                continue
            thread_starts = process.attributes.get("thread_start_addrs", []) or []
            for region in rwx_regions:
                start = region.attributes.get("start", 0)
                end = region.attributes.get("end", 0)
                for t_start in thread_starts:
                    if start <= int(t_start) < end:
                        findings.append(
                            self.finding(
                                description=(
                                    f"PID {process.attributes.get('pid', '?')} thread "
                                    f"starts at {hex(int(t_start))} inside RWX region "
                                    f"{hex(int(start))}-{hex(int(end))}"
                                ),
                                entity_ids=[process.entity_id, region.entity_id],
                                evidence={"thread_start": int(t_start)},
                            )
                        )
        return findings


class CredentialExfilChainRule(CorrelationRule):
    """Process reads /etc/shadow (or LSASS) and opens a network flow shortly after."""

    rule_id = "CRED_ACCESS_EXFIL_CHAIN"
    name = "Credential read followed by network egress"
    description = (
        "A process accessed a credential store and opened an outbound network "
        "flow within 60 seconds. Classic credential-exfil causal chain."
    )
    mitre_techniques = ("T1003", "T1041")
    severity = FindingSeverity.CRITICAL

    WINDOW_NS = 60 * 1_000_000_000

    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        cred_files = {"/etc/shadow", "/etc/gshadow", "/etc/master.passwd"}
        for process in ctx.graph.entities(EntityKind.PROCESS):
            read_edges = [
                e
                for e in ctx.graph.outgoing(process.entity_id, RelationType.READ)
                + ctx.graph.outgoing(process.entity_id, RelationType.OPENED)
            ]
            cred_reads = []
            for e in read_edges:
                target = ctx.graph.get_entity(e.dst)
                if target.kind != EntityKind.FILE:
                    continue
                path = getattr(target, "path", "") or str(target.attributes.get("path", ""))
                labels = target.labels
                if path in cred_files or "lsass" in path.lower() or "credential" in labels:
                    cred_reads.append((e.timestamp_ns, e.dst))
            if not cred_reads:
                continue
            connect_edges = ctx.graph.outgoing(process.entity_id, RelationType.CONNECTED_TO)
            for cred_ts, cred_id in cred_reads:
                for conn in connect_edges:
                    if conn.timestamp_ns - cred_ts <= self.WINDOW_NS and conn.timestamp_ns >= cred_ts:
                        findings.append(
                            self.finding(
                                description=(
                                    f"PID {process.attributes.get('pid', '?')} read credential "
                                    f"{cred_id} then connected to {conn.dst}"
                                ),
                                entity_ids=[process.entity_id, cred_id, conn.dst],
                                timestamp_ns=conn.timestamp_ns,
                            )
                        )
        return findings


class PamTamperRule(CorrelationRule):
    """A non-system process writes to a PAM config file."""

    rule_id = "DEFENSE_EVASION_PAM_TAMPER"
    name = "PAM config modified by non-packager process"
    description = (
        "A process outside the distro package manager wrote to a file in "
        "/etc/pam.d — persistence + defense-evasion signal."
    )
    mitre_techniques = ("T1556.003",)
    severity = FindingSeverity.HIGH

    PACKAGE_MANAGERS = {"dpkg", "apt", "rpm", "dnf", "yum", "zypper", "pacman"}

    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for process in ctx.graph.entities(EntityKind.PROCESS):
            comm = str(getattr(process, "comm", "") or process.attributes.get("comm", ""))
            if comm in self.PACKAGE_MANAGERS:
                continue
            for edge in ctx.graph.outgoing(process.entity_id, RelationType.WROTE):
                target = ctx.graph.get_entity(edge.dst)
                path = getattr(target, "path", "") or str(target.attributes.get("path", ""))
                if path.startswith("/etc/pam.d/") or path == "/etc/pam.conf":
                    findings.append(
                        self.finding(
                            description=(
                                f"Process {comm} (PID {process.attributes.get('pid', '?')}) "
                                f"wrote to PAM config {path}"
                            ),
                            entity_ids=[process.entity_id, target.entity_id],
                            timestamp_ns=edge.timestamp_ns,
                        )
                    )
        return findings


class PtraceAttachRule(CorrelationRule):
    """Ptrace attach against a credential-custodian process."""

    rule_id = "CRED_ACCESS_PTRACE"
    name = "Ptrace attach to credential process"
    description = (
        "A process attached to a credential-holding target via ptrace / "
        "process_vm_readv. This is how Linux LSASS-equivalents get dumped."
    )
    mitre_techniques = ("T1003.007", "T1055.008")
    severity = FindingSeverity.HIGH

    TARGETS = {"sshd", "gnome-keyring", "polkitd", "sudo", "su", "login", "lightdm", "systemd"}

    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for edge in ctx.graph.edges():
            if edge.relation != RelationType.INJECTED_INTO:
                continue
            target = ctx.graph.get_entity(edge.dst)
            if target.kind != EntityKind.PROCESS:
                continue
            t_comm = str(getattr(target, "comm", "") or target.attributes.get("comm", ""))
            if t_comm not in self.TARGETS:
                continue
            findings.append(
                self.finding(
                    description=(
                        f"Process {edge.src} attached to credential process "
                        f"{t_comm} (pid "
                        f"{target.attributes.get('pid', '?')})"
                    ),
                    entity_ids=[edge.src, target.entity_id],
                    timestamp_ns=edge.timestamp_ns,
                )
            )
        return findings


class OrphanedBpfRule(CorrelationRule):
    """An eBPF program is present but has no traced loader ancestor."""

    rule_id = "ROOTKIT_ORPHAN_BPF"
    name = "Orphaned eBPF program (possible BPF rootkit)"
    description = (
        "An eBPF program is present on the host, but no loading process "
        "exists in the traced process graph. Matches bpfdoor / boopkit / "
        "symbiote class rootkits that install then self-erase."
    )
    mitre_techniques = ("T1014", "T1547")
    severity = FindingSeverity.CRITICAL

    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for module in ctx.graph.entities(EntityKind.MODULE):
            if "bpf" not in module.labels and "ebpf_program" not in module.attributes.get("kind", ""):
                continue
            loaded_by = ctx.graph.incoming(module.entity_id, RelationType.LOADED)
            if loaded_by:
                continue
            findings.append(
                self.finding(
                    description=(
                        f"eBPF program {module.entity_id} has no loader in the "
                        f"correlation graph"
                    ),
                    entity_ids=[module.entity_id],
                )
            )
        return findings


class PersistenceNewUnitRule(CorrelationRule):
    """A persistence artifact flagged as deviation_from_baseline=True."""

    rule_id = "PERSISTENCE_NEW_UNIT"
    name = "New persistence artifact vs. baseline"
    description = (
        "A persistence mechanism was added since the last baseline snapshot."
    )
    mitre_techniques = ("T1543", "T1547", "T1053")
    severity = FindingSeverity.HIGH

    def match(self, ctx: RuleContext) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for entity in ctx.graph.entities(EntityKind.PERSISTENCE):
            if not entity.attributes.get("deviation_from_baseline"):
                continue
            if entity.attributes.get("_reported"):
                continue
            entity.attributes["_reported"] = True
            mech = getattr(entity, "mechanism", "") or str(entity.attributes.get("mechanism", ""))
            location = getattr(entity, "location", "") or str(entity.attributes.get("location", ""))
            mitre = getattr(entity, "mitre_technique", "") or str(entity.attributes.get("mitre_technique", ""))
            techniques = [mitre] if mitre else list(self.mitre_techniques)
            findings.append(
                CompositeFinding(
                    name=self.name,
                    rule_id=self.rule_id,
                    description=f"New {mech} persistence artifact: {location}",
                    severity=self.severity,
                    mitre_techniques=techniques,
                    entity_ids=[entity.entity_id],
                    evidence=dict(entity.attributes),
                )
            )
        return findings


DEFAULT_RULES: list[CorrelationRule] = [
    RWXInjectionRule(),
    CredentialExfilChainRule(),
    PamTamperRule(),
    PtraceAttachRule(),
    OrphanedBpfRule(),
    PersistenceNewUnitRule(),
]
