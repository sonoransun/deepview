"""Tests for the baseline / differential engine (Gap 4)."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.baseline import (
    DEFAULT_BASELINE_RULES,
    DeviationPublisher,
    HostSnapshot,
    SnapshotDiffer,
    SnapshotStore,
)
from deepview.baseline.rules import (
    CriticalFileMutationRule,
    NewEbpfProgramRule,
    NewKernelModuleRule,
    NewListenerRule,
    NewPersistenceRule,
    NewUserRule,
    run_rules,
)
from deepview.baseline.snapshot import (
    FileSample,
    MemoryPageDigest,
    NetworkSample,
    PersistenceSample,
    ProcessSample,
)
from deepview.core.events import BaselineDeviationEvent, EventBus, MemoryDiffEvent


def _base_snapshot() -> HostSnapshot:
    return HostSnapshot(
        host_id="victim",
        processes=[
            ProcessSample(pid=1, ppid=0, comm="init", start_time_ns=1000),
            ProcessSample(pid=200, ppid=1, comm="sshd", start_time_ns=1500),
        ],
        kernel_modules=["kvm", "loop", "ext4"],
        ebpf_programs=[],
        users=["root", "user1"],
        network=[],
        persistence=[],
        critical_files=[FileSample(path="/etc/passwd", sha256="a" * 64, size=1000)],
    )


def _current_snapshot(evil: bool = True) -> HostSnapshot:
    if not evil:
        return _base_snapshot()
    return HostSnapshot(
        host_id="victim",
        processes=[
            ProcessSample(pid=1, ppid=0, comm="init", start_time_ns=1000),
            ProcessSample(pid=200, ppid=1, comm="sshd", start_time_ns=1500),
            ProcessSample(pid=9999, ppid=1, comm="backdoor", start_time_ns=2000, cmdline=["/tmp/x"]),
        ],
        kernel_modules=["kvm", "loop", "ext4", "rootkit"],
        ebpf_programs=["bpfdoor"],
        users=["root", "user1", "hacker"],
        network=[
            NetworkSample(
                protocol="tcp",
                state="LISTEN",
                local_ip="0.0.0.0",
                local_port=31337,
            )
        ],
        persistence=[
            PersistenceSample(
                mechanism="cron",
                location="/etc/cron.d/backdoor",
                fingerprint="xyz",
                mitre_technique="T1053.003",
            )
        ],
        critical_files=[FileSample(path="/etc/passwd", sha256="b" * 64, size=1100)],
    )


class TestDiffer:
    def test_idempotent_self_diff(self) -> None:
        base = _base_snapshot()
        delta = SnapshotDiffer().diff(base, base)
        assert delta.is_empty()

    def test_attack_diff_produces_every_category(self) -> None:
        delta = SnapshotDiffer().diff(_base_snapshot(), _current_snapshot())
        assert len(delta.processes.spawned) == 1
        assert "rootkit" in delta.kernel_modules.loaded
        assert "bpfdoor" in delta.ebpf_programs.loaded
        assert delta.new_users == ["hacker"]
        assert len(delta.network.new_listeners) == 1
        assert len(delta.persistence.added) == 1
        assert len(delta.filesystem.modified) == 1

    def test_memory_digest_delta(self) -> None:
        base = _base_snapshot()
        current = _base_snapshot()
        base.memory_digest = MemoryPageDigest(
            page_size=4096, digests={0: "aa", 4096: "bb", 8192: "cc"}
        )
        current.memory_digest = MemoryPageDigest(
            page_size=4096,
            digests={0: "aa", 4096: "bb_changed", 12288: "dd"},
        )
        delta = SnapshotDiffer().diff(base, current)
        assert delta.memory is not None
        assert 4096 in delta.memory.changed_pages
        assert 12288 in delta.memory.new_pages
        assert 8192 in delta.memory.removed_pages
        assert delta.memory.change_rate > 0


class TestPublisher:
    def test_publishes_baseline_and_memory_events(self) -> None:
        bus = EventBus()
        received: list = []
        bus.subscribe(BaselineDeviationEvent, received.append)
        bus.subscribe(MemoryDiffEvent, received.append)
        base = _base_snapshot()
        current = _current_snapshot()
        base.memory_digest = MemoryPageDigest(digests={0: "aa"})
        current.memory_digest = MemoryPageDigest(digests={0: "bb"})
        delta = SnapshotDiffer().diff(base, current)
        pub = DeviationPublisher(bus)
        count = pub.publish(delta)
        assert count >= 6
        categories = {getattr(e, "category", None) for e in received if isinstance(e, BaselineDeviationEvent)}
        assert "processes" in categories
        assert "kernel_modules" in categories
        assert "persistence" in categories
        memory_events = [e for e in received if isinstance(e, MemoryDiffEvent)]
        assert memory_events, "MemoryDiffEvent must be published"

    def test_no_publish_on_empty_delta(self) -> None:
        bus = EventBus()
        received: list = []
        bus.subscribe(BaselineDeviationEvent, received.append)
        delta = SnapshotDiffer().diff(_base_snapshot(), _base_snapshot())
        DeviationPublisher(bus).publish(delta)
        assert not received


class TestRules:
    def test_default_rules_fire(self) -> None:
        delta = SnapshotDiffer().diff(_base_snapshot(), _current_snapshot())
        findings = run_rules(delta)
        rule_ids = {f.rule_id for f in findings}
        for expected in (
            "BASELINE_NEW_LKM",
            "BASELINE_NEW_BPF",
            "BASELINE_NEW_LISTENER",
            "BASELINE_NEW_USER",
            "BASELINE_NEW_PERSISTENCE",
            "BASELINE_CRITICAL_FILE_CHANGE",
        ):
            assert expected in rule_ids

    def test_benign_port_not_flagged(self) -> None:
        base = _base_snapshot()
        current = _base_snapshot()
        current.network = [
            NetworkSample(
                protocol="tcp",
                state="LISTEN",
                local_ip="0.0.0.0",
                local_port=22,
            )
        ]
        delta = SnapshotDiffer().diff(base, current)
        findings = NewListenerRule().match(delta)
        assert not findings


class TestStore:
    def test_roundtrip(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "snap.db")
        snap = _base_snapshot()
        store.save(snap)
        loaded = store.load(snap.snapshot_id)
        assert loaded.host_id == snap.host_id
        assert len(loaded.processes) == len(snap.processes)
        listing = store.list_snapshots("victim")
        assert listing
        latest = store.latest("victim")
        assert latest is not None and latest.snapshot_id == snap.snapshot_id

    def test_delete(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "snap.db")
        snap = _base_snapshot()
        store.save(snap)
        store.delete(snap.snapshot_id)
        with pytest.raises(Exception):
            store.load(snap.snapshot_id)

    def test_missing_returns_none(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "snap.db")
        assert store.latest("ghost") is None
