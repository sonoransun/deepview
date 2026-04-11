"""Baseline deviation rules → CompositeFinding with MITRE mapping.

These rules inspect a :class:`SnapshotDelta` and produce composite findings
that are pushed into the correlation graph. Think of them as the
"differential detectors" — signals you can only see by comparing two
snapshots rather than inspecting one in isolation.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from deepview.baseline.differ import SnapshotDelta
from deepview.core.correlation.composite_events import CompositeFinding, FindingSeverity


class BaselineRule(ABC):
    rule_id: str = ""
    name: str = ""
    description: str = ""
    mitre_techniques: tuple[str, ...] = ()
    severity: FindingSeverity = FindingSeverity.MEDIUM

    @abstractmethod
    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        ...

    def _finding(
        self,
        *,
        description: str,
        entity_ids: list[str] | None = None,
        evidence: dict[str, object] | None = None,
        severity: FindingSeverity | None = None,
    ) -> CompositeFinding:
        return CompositeFinding(
            name=self.name or self.rule_id,
            rule_id=self.rule_id,
            description=description,
            severity=severity or self.severity,
            mitre_techniques=list(self.mitre_techniques),
            entity_ids=list(entity_ids or []),
            evidence=evidence or {},
        )


# ---------------------------------------------------------------------------


class NewKernelModuleRule(BaselineRule):
    rule_id = "BASELINE_NEW_LKM"
    name = "New kernel module since baseline"
    description = "A kernel module is present in the current snapshot that was not in the baseline."
    mitre_techniques = ("T1014", "T1547.006")
    severity = FindingSeverity.CRITICAL

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for mod in delta.kernel_modules.loaded:
            findings.append(
                self._finding(
                    description=f"Kernel module {mod} loaded since baseline",
                    evidence={"module": mod},
                )
            )
        return findings


class NewEbpfProgramRule(BaselineRule):
    rule_id = "BASELINE_NEW_BPF"
    name = "New eBPF program since baseline"
    description = (
        "An eBPF program appeared since the last baseline. eBPF rootkits "
        "(bpfdoor / symbiote class) install persistent programs this way."
    )
    mitre_techniques = ("T1014",)
    severity = FindingSeverity.CRITICAL

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        return [
            self._finding(
                description=f"eBPF program {name} loaded since baseline",
                evidence={"program": name},
            )
            for name in delta.ebpf_programs.loaded
        ]


class NewListenerRule(BaselineRule):
    rule_id = "BASELINE_NEW_LISTENER"
    name = "Unexpected listening port"
    description = "A process is bound to a port that did not exist in the baseline."
    mitre_techniques = ("T1571", "T1205")
    severity = FindingSeverity.HIGH

    # Ports that are considered benign even when new (common legitimate services).
    _BENIGN_PORTS = {22, 53, 80, 443, 631, 5353}

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for listener in delta.network.new_listeners:
            if listener.local_port in self._BENIGN_PORTS:
                continue
            findings.append(
                self._finding(
                    description=(
                        f"New {listener.protocol} listener "
                        f"{listener.local_ip}:{listener.local_port}"
                    ),
                    evidence={"listener": listener.model_dump()},
                )
            )
        return findings


class NewUserRule(BaselineRule):
    rule_id = "BASELINE_NEW_USER"
    name = "New local user account"
    description = "A user account was added since the baseline snapshot."
    mitre_techniques = ("T1136.001",)
    severity = FindingSeverity.HIGH

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        return [
            self._finding(
                description=f"Local user {user} added",
                evidence={"user": user},
            )
            for user in delta.new_users
        ]


class NewPersistenceRule(BaselineRule):
    rule_id = "BASELINE_NEW_PERSISTENCE"
    name = "New persistence artifact"
    description = "A persistence mechanism was added since the last baseline."
    mitre_techniques = ("T1543", "T1547", "T1053")
    severity = FindingSeverity.HIGH

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        return [
            self._finding(
                description=f"New persistence: {p.mechanism} @ {p.location}",
                evidence={"mechanism": p.mechanism, "mitre": p.mitre_technique},
            )
            for p in delta.persistence.added
        ]


class CriticalFileMutationRule(BaselineRule):
    rule_id = "BASELINE_CRITICAL_FILE_CHANGE"
    name = "Critical file hash changed"
    description = (
        "A file tracked as a baseline integrity target changed hash. "
        "Used for /etc/ssh/sshd_config, /etc/shadow, PAM stacks, etc."
    )
    mitre_techniques = ("T1565.001",)
    severity = FindingSeverity.HIGH

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        findings: list[CompositeFinding] = []
        for old, new in delta.filesystem.modified:
            findings.append(
                self._finding(
                    description=f"File {old.path} hash changed: {old.sha256[:12]} -> {new.sha256[:12]}",
                    evidence={"path": old.path, "old": old.sha256, "new": new.sha256},
                )
            )
        return findings


class MemoryHighChurnRule(BaselineRule):
    rule_id = "BASELINE_MEMORY_HIGH_CHURN"
    name = "High memory-page churn between snapshots"
    description = (
        "The ratio of changed/new/removed pages in the memory image exceeds "
        "a threshold. Large churn on a supposedly idle host is suspicious."
    )
    mitre_techniques = ("T1014",)
    severity = FindingSeverity.MEDIUM

    THRESHOLD = 0.10

    def match(self, delta: SnapshotDelta) -> list[CompositeFinding]:
        if delta.memory is None:
            return []
        if delta.memory.change_rate < self.THRESHOLD:
            return []
        return [
            self._finding(
                description=(
                    f"Memory page churn {delta.memory.change_rate:.1%} exceeds "
                    f"{self.THRESHOLD:.0%} threshold"
                ),
                evidence={
                    "changed": len(delta.memory.changed_pages),
                    "new": len(delta.memory.new_pages),
                    "removed": len(delta.memory.removed_pages),
                    "total": delta.memory.page_count,
                },
            )
        ]


DEFAULT_BASELINE_RULES: list[BaselineRule] = [
    NewKernelModuleRule(),
    NewEbpfProgramRule(),
    NewListenerRule(),
    NewUserRule(),
    NewPersistenceRule(),
    CriticalFileMutationRule(),
    MemoryHighChurnRule(),
]


def run_rules(
    delta: SnapshotDelta,
    rules: Iterable[BaselineRule] | None = None,
) -> list[CompositeFinding]:
    rules = list(rules or DEFAULT_BASELINE_RULES)
    results: list[CompositeFinding] = []
    for rule in rules:
        try:
            results.extend(rule.match(delta))
        except Exception:  # pragma: no cover
            continue
    return results
