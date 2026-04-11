"""Baseline delta source — renders a :class:`SnapshotDelta` as timeline rows."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

from deepview.baseline.differ import SnapshotDelta
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent


class BaselineSource:
    source_type = SourceType.BASELINE

    def __init__(
        self,
        delta: SnapshotDelta,
        *,
        host_id: str = "localhost",
        observed_at: datetime | None = None,
    ) -> None:
        self.delta = delta
        self.host_id = host_id
        self.observed_at = observed_at or datetime.now(timezone.utc)

    def events(self) -> Iterator[TimelineEvent]:
        d = self.delta
        for proc in d.processes.spawned:
            yield self._event(
                description=f"Baseline: process spawned pid={proc.pid} comm={proc.comm}",
                severity=Severity.MEDIUM,
                entity_id=f"process:{proc.pid}",
                mitre=[],
                raw={"kind": "processes.spawned"},
            )
        for mod in d.kernel_modules.loaded:
            yield self._event(
                description=f"Baseline: kernel module loaded {mod}",
                severity=Severity.CRITICAL,
                entity_id=f"module:{mod}",
                mitre=["T1014"],
                raw={"kind": "kernel_modules.loaded"},
            )
        for bpf in d.ebpf_programs.loaded:
            yield self._event(
                description=f"Baseline: eBPF program loaded {bpf}",
                severity=Severity.CRITICAL,
                entity_id=f"bpf:{bpf}",
                mitre=["T1014"],
                raw={"kind": "ebpf.loaded"},
            )
        for listener in d.network.new_listeners:
            yield self._event(
                description=(
                    f"Baseline: new {listener.protocol} listener "
                    f"{listener.local_ip}:{listener.local_port}"
                ),
                severity=Severity.HIGH,
                entity_id=f"listener:{listener.protocol}:{listener.local_port}",
                mitre=["T1571"],
                raw={"kind": "network.new_listener"},
            )
        for user in d.new_users:
            yield self._event(
                description=f"Baseline: new user {user}",
                severity=Severity.HIGH,
                entity_id=f"user:{user}",
                mitre=["T1136.001"],
                raw={"kind": "users.added"},
            )
        for persistence in d.persistence.added:
            yield self._event(
                description=f"Baseline: persistence added {persistence.mechanism} @ {persistence.location}",
                severity=Severity.HIGH,
                entity_id=f"persist:{persistence.mechanism}:{persistence.location}",
                mitre=[persistence.mitre_technique] if persistence.mitre_technique else [],
                raw={"kind": "persistence.added"},
            )
        for old, new in d.filesystem.modified:
            yield self._event(
                description=f"Baseline: file modified {old.path}",
                severity=Severity.MEDIUM,
                entity_id=f"file:{old.path}",
                mitre=["T1565.001"],
                raw={"kind": "filesystem.modified", "old_sha": old.sha256, "new_sha": new.sha256},
            )

    def _event(
        self,
        *,
        description: str,
        severity: Severity,
        entity_id: str,
        mitre: list[str],
        raw: dict[str, Any],
    ) -> TimelineEvent:
        return TimelineEvent(
            timestamp_utc=self.observed_at,
            timestamp_source="inferred",
            host_id=self.host_id,
            entity_id=entity_id,
            source=SourceType.BASELINE,
            description=description,
            severity=severity,
            mitre_techniques=list(mitre),
            raw=raw,
        )
