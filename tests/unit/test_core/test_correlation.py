"""Tests for the cross-subsystem correlation engine."""
from __future__ import annotations

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.correlation import (
    CompositeFindingEvent,
    CorrelationEngine,
    CorrelationGraph,
    EntityKind,
    FileEntity,
    FindingSeverity,
    ProcessEntity,
    RelationType,
)
from deepview.core.correlation.rules import (
    CredentialExfilChainRule,
    PamTamperRule,
    PtraceAttachRule,
    RWXInjectionRule,
)
from deepview.core.exceptions import EntityNotFoundError
from deepview.core.types import ProcessContext, ThreadInfo


def _proc(pid: int, comm: str, ppid: int = 1, **kwargs: object) -> ProcessContext:
    return ProcessContext(pid=pid, ppid=ppid, comm=comm, exe_path=f"/bin/{comm}", **kwargs)  # type: ignore[arg-type]


class TestCorrelationGraph:
    def test_entity_merge_keeps_first_attributes(self) -> None:
        g = CorrelationGraph()
        a = ProcessEntity(entity_id="process:1", pid=1, comm="init")
        a.attributes["rich"] = "value"
        g.add_entity(a)
        b = ProcessEntity(entity_id="process:1", pid=1, comm="")
        # empty values shouldn't wipe existing rich data
        g.add_entity(b)
        merged = g.get_entity("process:1")
        assert merged.attributes["rich"] == "value"

    def test_add_edge_requires_both_endpoints(self) -> None:
        g = CorrelationGraph()
        g.add_entity(ProcessEntity(entity_id="process:1", pid=1))
        with pytest.raises(EntityNotFoundError):
            g.add_edge("process:1", "missing", RelationType.SPAWNED)

    def test_walk_from_is_cycle_safe(self) -> None:
        g = CorrelationGraph()
        g.add_entity(ProcessEntity(entity_id="process:1", pid=1))
        g.add_entity(ProcessEntity(entity_id="process:2", pid=2))
        g.add_edge("process:1", "process:2", RelationType.SPAWNED)
        g.add_edge("process:2", "process:1", RelationType.SPAWNED)  # cycle
        reached = list(g.walk_from("process:1", [RelationType.SPAWNED]))
        assert {e.entity_id for e in reached} == {"process:1", "process:2"}

    def test_merge_is_idempotent(self) -> None:
        g = CorrelationGraph()
        g.add_entity(ProcessEntity(entity_id="process:1", pid=1))
        g.add_entity(ProcessEntity(entity_id="process:2", pid=2))
        g.add_edge("process:1", "process:2", RelationType.SPAWNED, timestamp_ns=100)
        nodes_before, edges_before = g.size()
        g.merge(g.__class__().__init__() or g)  # noqa - we mean merge(self)
        g.merge(g)
        nodes_after, edges_after = g.size()
        assert nodes_before == nodes_after
        assert edges_before == edges_after

    def test_merge_two_distinct_graphs(self) -> None:
        g1 = CorrelationGraph()
        g1.add_entity(ProcessEntity(entity_id="process:1", pid=1))
        g2 = CorrelationGraph()
        g2.add_entity(ProcessEntity(entity_id="process:1", pid=1, comm="init"))
        g2.add_entity(ProcessEntity(entity_id="process:2", pid=2))
        g2.add_edge("process:1", "process:2", RelationType.SPAWNED)
        g1.merge(g2)
        assert g1.size() == (2, 1)
        assert g1.get_entity("process:2") is not None


class TestRulesFire:
    def test_rwx_injection_rule(self) -> None:
        engine = CorrelationEngine()
        engine.register_rule(RWXInjectionRule())
        proc = _proc(
            100,
            "x",
            threads=[ThreadInfo(tid=1, start_address=0x100500)],
        )
        engine.record_process(proc)
        engine.record_memory_region(proc, start=0x100000, end=0x101000, protection="RWX")
        findings = engine.run_rules()
        assert any(f.rule_id == "INJECTION_RWX_THREAD" for f in findings)

    def test_cred_exfil_chain(self) -> None:
        engine = CorrelationEngine()
        engine.register_rule(CredentialExfilChainRule())
        proc = _proc(200, "curl")
        engine.record_process(proc)
        engine.record_file_access(proc, "/etc/shadow", timestamp_ns=10 * 1_000_000_000)
        engine.record_network_flow(
            proc,
            protocol="tcp",
            src_ip="10.0.0.1",
            src_port=5555,
            dst_ip="1.2.3.4",
            dst_port=443,
            timestamp_ns=15 * 1_000_000_000,
        )
        findings = engine.run_rules()
        assert any(f.rule_id == "CRED_ACCESS_EXFIL_CHAIN" for f in findings)

    def test_pam_tamper(self) -> None:
        engine = CorrelationEngine()
        engine.register_rule(PamTamperRule())
        attacker = _proc(300, "sh")
        engine.record_process(attacker)
        engine.record_file_access(
            attacker,
            "/etc/pam.d/sshd",
            relation=RelationType.WROTE,
            timestamp_ns=5_000_000_000,
        )
        findings = engine.run_rules()
        assert any(f.rule_id == "DEFENSE_EVASION_PAM_TAMPER" for f in findings)

    def test_package_manager_bypass(self) -> None:
        """Writes from dpkg to /etc/pam.d should NOT trip the rule."""
        engine = CorrelationEngine()
        engine.register_rule(PamTamperRule())
        proc = _proc(400, "dpkg")
        engine.record_process(proc)
        engine.record_file_access(
            proc,
            "/etc/pam.d/common-auth",
            relation=RelationType.WROTE,
            timestamp_ns=5_000_000_000,
        )
        findings = engine.run_rules()
        assert not any(f.rule_id == "DEFENSE_EVASION_PAM_TAMPER" for f in findings)

    def test_ptrace_attach_to_sshd(self) -> None:
        engine = CorrelationEngine()
        engine.register_rule(PtraceAttachRule())
        attacker = _proc(500, "gdb")
        victim = _proc(20, "sshd", ppid=1)
        engine.record_process(attacker)
        engine.record_process(victim)
        engine.record_injection(attacker, victim, timestamp_ns=9_000_000_000)
        findings = engine.run_rules()
        assert any(f.rule_id == "CRED_ACCESS_PTRACE" for f in findings)


class TestEnginePublishing:
    def test_finding_published_to_event_bus(self) -> None:
        ctx = AnalysisContext.for_testing()
        received: list[CompositeFindingEvent] = []
        ctx.events.subscribe(CompositeFindingEvent, received.append)

        eng = ctx.correlation  # already has default rules
        proc = _proc(
            777,
            "beacon",
            threads=[ThreadInfo(tid=1, start_address=0x500500)],
        )
        eng.record_process(proc)
        eng.record_memory_region(proc, start=0x500000, end=0x501000, protection="RWX")
        eng.run_rules()
        assert received, "composite finding should land on the event bus"
        assert received[0].finding.mitre_techniques == ["T1055"]
        assert received[0].severity == FindingSeverity.HIGH

    def test_dedup_across_runs(self) -> None:
        engine = CorrelationEngine()
        engine.register_rule(RWXInjectionRule())
        proc = _proc(
            888,
            "x",
            threads=[ThreadInfo(tid=1, start_address=0x600500)],
        )
        engine.record_process(proc)
        engine.record_memory_region(proc, start=0x600000, end=0x601000, protection="RWX")
        first = engine.run_rules()
        second = engine.run_rules()
        assert first, "first run should produce the injection finding"
        assert not second, "second run must not duplicate"


class TestProcessContextStableKey:
    def test_key_with_boot_ns(self) -> None:
        pc = ProcessContext(pid=42, comm="x")
        assert pc.stable_key() == "process:42"
        assert pc.stable_key(boot_ns=111) == "process:42@111"
