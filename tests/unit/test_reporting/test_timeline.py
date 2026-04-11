"""Tests for the unified timeline + causality (Gap 5)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from deepview.baseline.differ import SnapshotDiffer
from deepview.baseline.snapshot import (
    FileSample,
    HostSnapshot,
    NetworkSample,
    ProcessSample,
)
from deepview.core.correlation import CorrelationGraph, ProcessEntity, RelationType
from deepview.core.types import EventCategory, ProcessContext
from deepview.detection.persistence.base import PersistenceArtifact, PersistenceSeverity
from deepview.reporting.timeline import (
    CausalChain,
    CausalityBuilder,
    Severity,
    SourceType,
    TimelineBuilder,
    TimelineEvent,
    TimelineMerger,
    TimestompingDetector,
    write_plaso_csv,
)
from deepview.reporting.timeline.sources import (
    BaselineSource,
    FilesystemSource,
    PersistenceSource,
    TraceEventSource,
)
from deepview.reporting.timeline.timestomping import FileTimes
from deepview.tracing.events import MonitorEvent


def _trace_event(pid: int, category: EventCategory, args: dict, wall: datetime) -> MonitorEvent:
    return MonitorEvent(
        category=category,
        process=ProcessContext(pid=pid, comm="sh"),
        wall_clock_ns=int(wall.timestamp() * 1e9),
        args=dict(args),
    )


class TestMerger:
    def test_merges_and_sorts(self) -> None:
        merger = TimelineMerger()
        events = [
            _trace_event(1, EventCategory.PROCESS_EXEC, {"argv": ["a"]}, datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)),
            _trace_event(1, EventCategory.FILE_ACCESS, {"operation": "open", "path": "/etc/passwd"}, datetime(2026, 4, 1, 12, 0, 10, tzinfo=timezone.utc)),
        ]
        merger.add_source(TraceEventSource(events))
        out = merger.build()
        assert len(out) == 2
        assert out[0].timestamp_utc < out[1].timestamp_utc

    def test_dedup_promotes_severity(self) -> None:
        merger = TimelineMerger()
        ts = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
        a = TimelineEvent(
            timestamp_utc=ts,
            entity_id="process:1",
            source=SourceType.TRACE,
            description="duplicate",
            severity=Severity.INFO,
        )
        b = TimelineEvent(
            timestamp_utc=ts,
            entity_id="process:1",
            source=SourceType.TRACE,
            description="duplicate",
            severity=Severity.CRITICAL,
            mitre_techniques=["T1055"],
        )

        class StaticSource:
            source_type = SourceType.TRACE

            def events(self):
                yield a
                yield b

        merger.add_source(StaticSource())
        out = merger.build()
        assert len(out) == 1
        assert out[0].severity is Severity.CRITICAL
        assert out[0].mitre_techniques == ["T1055"]


class TestTimestomping:
    def test_ext4_ctime_before_mtime(self) -> None:
        det = TimestompingDetector(now=datetime(2026, 4, 11, tzinfo=timezone.utc))
        ft = FileTimes(
            path="/bin/x",
            ctime=datetime(2020, 1, 1, 12, 30, 45, tzinfo=timezone.utc),
            mtime=datetime(2025, 1, 1, 12, 30, 45, tzinfo=timezone.utc),
        )
        findings = det.scan([ft])
        assert any("ctime earlier than mtime" in f.reason for f in findings)

    def test_ntfs_fn_newer_than_si(self) -> None:
        det = TimestompingDetector(now=datetime(2026, 4, 11, tzinfo=timezone.utc))
        ft = FileTimes(
            path="/evil.exe",
            mtime=datetime(2020, 1, 1, 12, 30, 45, tzinfo=timezone.utc),
            fn_mtime=datetime(2025, 1, 1, 12, 30, 45, tzinfo=timezone.utc),
        )
        findings = det.scan([ft])
        assert any("FILE_NAME" in f.reason for f in findings)

    def test_zero_precision_fingerprint(self) -> None:
        det = TimestompingDetector(now=datetime(2026, 4, 11, tzinfo=timezone.utc))
        ft = FileTimes(
            path="/tmp/x",
            mtime=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        findings = det.scan([ft])
        assert any("touch -t" in f.reason for f in findings)


class TestCausality:
    def test_forward_chain(self) -> None:
        g = CorrelationGraph()
        for i in range(3):
            g.add_entity(ProcessEntity(entity_id=f"process:{i}", pid=i))
        g.add_edge("process:0", "process:1", RelationType.SPAWNED, timestamp_ns=100)
        g.add_edge("process:1", "process:2", RelationType.SPAWNED, timestamp_ns=200)
        chains = CausalityBuilder(g).chains()
        assert any(c.root == "process:0" and c.tail == "process:2" for c in chains)


class TestLegacyCompat:
    def test_timeline_builder_accepts_legacy_entry(self) -> None:
        from deepview.reporting.timeline.event import TimelineEntry

        tb = TimelineBuilder()
        tb.add_entry(TimelineEntry(event_type="exec", description="foo", pid=1))
        assert tb.entry_count == 1
        out = tb.build()
        assert out[0].description == "foo"


class TestSuperTimelineExport:
    def test_plaso_csv_roundtrip(self, tmp_path: Path) -> None:
        events = [
            TimelineEvent(
                timestamp_utc=datetime(2026, 4, 11, 10, 0, 0, tzinfo=timezone.utc),
                source=SourceType.TRACE,
                description="exec /bin/sh",
                severity=Severity.MEDIUM,
                mitre_techniques=["T1059"],
            )
        ]
        out = tmp_path / "super.csv"
        count = write_plaso_csv(events, out)
        assert count == 1
        content = out.read_text(encoding="utf-8")
        assert "exec /bin/sh" in content
        assert "T1059" in content


class TestBaselineSource:
    def test_emits_all_categories(self) -> None:
        base = HostSnapshot(host_id="victim")
        current = HostSnapshot(
            host_id="victim",
            kernel_modules=["evil"],
            ebpf_programs=["bpfdoor"],
            users=["root", "attacker"],
            network=[
                NetworkSample(
                    protocol="tcp",
                    state="LISTEN",
                    local_ip="0.0.0.0",
                    local_port=31337,
                )
            ],
        )
        delta = SnapshotDiffer().diff(base, current)
        src = BaselineSource(delta, host_id="victim")
        events = list(src.events())
        descriptions = [e.description for e in events]
        assert any("kernel module" in d for d in descriptions)
        assert any("eBPF program" in d for d in descriptions)
        assert any("listener" in d for d in descriptions)
        assert any("new user" in d for d in descriptions)


class TestPersistenceSource:
    def test_emits_with_mitre(self) -> None:
        findings = [
            PersistenceArtifact(
                mechanism="cron",
                location="/etc/cron.d/x",
                last_modified=datetime(2026, 4, 1, tzinfo=timezone.utc),
                severity=PersistenceSeverity.HIGH,
                mitre_technique="T1053.003",
            )
        ]
        src = PersistenceSource(findings)
        events = list(src.events())
        assert events
        assert events[0].mitre_techniques == ["T1053.003"]
        assert events[0].severity is Severity.HIGH


class TestFilesystemSourceWithTimestomping:
    def test_emits_and_detects(self, tmp_path: Path) -> None:
        path = tmp_path / "evil.txt"
        path.write_text("x")
        src = FilesystemSource([path], detect_timestomping=True)
        events = list(src.events())
        # at least 3 MACB rows and maybe a timestomp row
        assert any(e.source is SourceType.FILESYSTEM for e in events)
        assert any("mtime" in e.description or "ctime" in e.description or "atime" in e.description for e in events)
