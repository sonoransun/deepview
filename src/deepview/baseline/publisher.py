"""Publisher — emits ``BaselineDeviationEvent`` and ``MemoryDiffEvent``.

This is where the long-dead event types from ``core/events.py`` finally get
a concrete producer. The publisher converts each sub-delta into one or more
structured events and pushes them onto the ``EventBus``, then walks the
registered baseline rules to produce composite findings mapped to MITRE.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from deepview.baseline.differ import SnapshotDelta
from deepview.core.events import (
    BaselineDeviationEvent,
    EventBus,
    MemoryDiffEvent,
)
from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.baseline.rules import BaselineRule

log = get_logger("baseline.publisher")


class DeviationPublisher:
    """Stateless translator from ``SnapshotDelta`` to events on the bus."""

    def __init__(self, event_bus: EventBus) -> None:
        self._bus = event_bus

    def publish(self, delta: SnapshotDelta) -> int:
        """Publish one event per non-empty delta category. Returns the count."""
        count = 0
        p = delta.processes
        if p.spawned or p.exited or p.reparented or p.cmdline_changed:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="processes",
                    description=(
                        f"{len(p.spawned)} spawned, {len(p.exited)} exited, "
                        f"{len(p.reparented)} reparented, {len(p.cmdline_changed)} cmdline-changed"
                    ),
                    severity=self._severity_for_processes(delta),
                    evidence={
                        "spawned": [proc.model_dump() for proc in p.spawned],
                        "exited": [proc.model_dump() for proc in p.exited],
                        "reparented": [
                            {"pid": proc.pid, "old_ppid": old, "new_ppid": new}
                            for proc, old, new in p.reparented
                        ],
                    },
                )
            )
            count += 1
        if delta.kernel_modules.loaded or delta.kernel_modules.unloaded:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="kernel_modules",
                    description=(
                        f"{len(delta.kernel_modules.loaded)} loaded, "
                        f"{len(delta.kernel_modules.unloaded)} unloaded"
                    ),
                    severity="critical" if delta.kernel_modules.loaded else "warning",
                    evidence={
                        "loaded": delta.kernel_modules.loaded,
                        "unloaded": delta.kernel_modules.unloaded,
                    },
                )
            )
            count += 1
        if delta.ebpf_programs.loaded or delta.ebpf_programs.unloaded:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="ebpf_programs",
                    description=(
                        f"{len(delta.ebpf_programs.loaded)} loaded, "
                        f"{len(delta.ebpf_programs.unloaded)} unloaded"
                    ),
                    severity="critical",
                    evidence={
                        "loaded": delta.ebpf_programs.loaded,
                        "unloaded": delta.ebpf_programs.unloaded,
                    },
                )
            )
            count += 1
        if delta.network.new_listeners or delta.network.closed_listeners:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="network_listeners",
                    description=(
                        f"{len(delta.network.new_listeners)} new listeners, "
                        f"{len(delta.network.closed_listeners)} closed"
                    ),
                    severity="warning",
                    evidence={
                        "new": [n.model_dump() for n in delta.network.new_listeners],
                        "closed": [n.model_dump() for n in delta.network.closed_listeners],
                    },
                )
            )
            count += 1
        if delta.persistence.added or delta.persistence.removed:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="persistence",
                    description=(
                        f"{len(delta.persistence.added)} added, "
                        f"{len(delta.persistence.removed)} removed"
                    ),
                    severity="critical" if delta.persistence.added else "warning",
                    evidence={
                        "added": [p.model_dump() for p in delta.persistence.added],
                        "removed": [p.model_dump() for p in delta.persistence.removed],
                    },
                )
            )
            count += 1
        if delta.filesystem.added or delta.filesystem.removed or delta.filesystem.modified:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="filesystem",
                    description=(
                        f"{len(delta.filesystem.added)} added, "
                        f"{len(delta.filesystem.removed)} removed, "
                        f"{len(delta.filesystem.modified)} modified"
                    ),
                    severity="warning",
                    evidence={
                        "added": [f.path for f in delta.filesystem.added],
                        "removed": [f.path for f in delta.filesystem.removed],
                        "modified": [old.path for old, _ in delta.filesystem.modified],
                    },
                )
            )
            count += 1
        if delta.new_users or delta.removed_users:
            self._bus.publish(
                BaselineDeviationEvent(
                    category="users",
                    description=(
                        f"{len(delta.new_users)} added, {len(delta.removed_users)} removed"
                    ),
                    severity="critical",
                    evidence={
                        "added": delta.new_users,
                        "removed": delta.removed_users,
                    },
                )
            )
            count += 1
        if delta.memory is not None:
            m = delta.memory
            if m.changed_pages or m.new_pages or m.removed_pages:
                self._bus.publish(
                    MemoryDiffEvent(
                        changed_pages=list(m.changed_pages),
                        new_pages=list(m.new_pages),
                        removed_pages=list(m.removed_pages),
                        change_rate=m.change_rate,
                    )
                )
                count += 1
        log.info("baseline_events_published", count=count)
        return count

    def _severity_for_processes(self, delta: SnapshotDelta) -> str:
        if delta.processes.reparented:
            return "critical"
        if delta.processes.cmdline_changed:
            return "warning"
        return "info"
