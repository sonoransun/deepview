"""Snapshot differ — takes two :class:`HostSnapshot`s and computes deltas."""
from __future__ import annotations

from dataclasses import dataclass, field

from deepview.baseline.snapshot import (
    FileSample,
    HostSnapshot,
    MemoryPageDigest,
    ModuleSample,
    NetworkSample,
    PersistenceSample,
    ProcessSample,
)


@dataclass
class ProcessDelta:
    spawned: list[ProcessSample] = field(default_factory=list)
    exited: list[ProcessSample] = field(default_factory=list)
    reparented: list[tuple[ProcessSample, int, int]] = field(default_factory=list)  # (proc, old_ppid, new_ppid)
    cmdline_changed: list[tuple[ProcessSample, list[str], list[str]]] = field(default_factory=list)


@dataclass
class ModuleDelta:
    loaded: list[ModuleSample] = field(default_factory=list)
    unloaded: list[ModuleSample] = field(default_factory=list)


@dataclass
class NetworkDelta:
    new_listeners: list[NetworkSample] = field(default_factory=list)
    closed_listeners: list[NetworkSample] = field(default_factory=list)
    new_connections: list[NetworkSample] = field(default_factory=list)
    closed_connections: list[NetworkSample] = field(default_factory=list)


@dataclass
class PersistenceDelta:
    added: list[PersistenceSample] = field(default_factory=list)
    removed: list[PersistenceSample] = field(default_factory=list)


@dataclass
class FilesystemDelta:
    added: list[FileSample] = field(default_factory=list)
    removed: list[FileSample] = field(default_factory=list)
    modified: list[tuple[FileSample, FileSample]] = field(default_factory=list)


@dataclass
class MemoryPageDelta:
    changed_pages: list[int] = field(default_factory=list)
    new_pages: list[int] = field(default_factory=list)
    removed_pages: list[int] = field(default_factory=list)
    page_count: int = 0

    @property
    def change_rate(self) -> float:
        if self.page_count == 0:
            return 0.0
        return (len(self.changed_pages) + len(self.new_pages) + len(self.removed_pages)) / self.page_count


@dataclass
class KernelModuleDelta:
    loaded: list[str] = field(default_factory=list)
    unloaded: list[str] = field(default_factory=list)


@dataclass
class EbpfProgramDelta:
    loaded: list[str] = field(default_factory=list)
    unloaded: list[str] = field(default_factory=list)


@dataclass
class SnapshotDelta:
    base_snapshot_id: str
    current_snapshot_id: str
    processes: ProcessDelta = field(default_factory=ProcessDelta)
    modules: ModuleDelta = field(default_factory=ModuleDelta)
    network: NetworkDelta = field(default_factory=NetworkDelta)
    persistence: PersistenceDelta = field(default_factory=PersistenceDelta)
    filesystem: FilesystemDelta = field(default_factory=FilesystemDelta)
    memory: MemoryPageDelta | None = None
    kernel_modules: KernelModuleDelta = field(default_factory=KernelModuleDelta)
    ebpf_programs: EbpfProgramDelta = field(default_factory=EbpfProgramDelta)
    new_users: list[str] = field(default_factory=list)
    removed_users: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        has_memory = self.memory is not None and (
            self.memory.changed_pages or self.memory.new_pages or self.memory.removed_pages
        )
        return not any(
            [
                self.processes.spawned,
                self.processes.exited,
                self.processes.reparented,
                self.processes.cmdline_changed,
                self.modules.loaded,
                self.modules.unloaded,
                self.network.new_listeners,
                self.network.closed_listeners,
                self.network.new_connections,
                self.network.closed_connections,
                self.persistence.added,
                self.persistence.removed,
                self.filesystem.added,
                self.filesystem.removed,
                self.filesystem.modified,
                has_memory,
                self.kernel_modules.loaded,
                self.kernel_modules.unloaded,
                self.ebpf_programs.loaded,
                self.ebpf_programs.unloaded,
                self.new_users,
                self.removed_users,
            ]
        )


class SnapshotDiffer:
    """Pure function: ``diff(base, current) -> SnapshotDelta``."""

    def diff(self, base: HostSnapshot, current: HostSnapshot) -> SnapshotDelta:
        delta = SnapshotDelta(
            base_snapshot_id=base.snapshot_id,
            current_snapshot_id=current.snapshot_id,
        )
        self._diff_processes(base, current, delta)
        self._diff_modules(base, current, delta)
        self._diff_network(base, current, delta)
        self._diff_persistence(base, current, delta)
        self._diff_files(base, current, delta)
        self._diff_memory(base, current, delta)
        self._diff_kernel_modules(base, current, delta)
        self._diff_ebpf(base, current, delta)
        self._diff_users(base, current, delta)
        return delta

    # ------------------------------------------------------------------

    def _diff_processes(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_by_key = {p.key(): p for p in base.processes}
        cur_by_key = {p.key(): p for p in current.processes}
        base_pids = {p.pid: p for p in base.processes}
        cur_pids = {p.pid: p for p in current.processes}
        spawned_keys = set(cur_by_key) - set(base_by_key)
        exited_keys = set(base_by_key) - set(cur_by_key)
        delta.processes.spawned = [cur_by_key[k] for k in sorted(spawned_keys)]
        delta.processes.exited = [base_by_key[k] for k in sorted(exited_keys)]
        # Reparenting: same pid both sides, different ppid
        for pid, cur in cur_pids.items():
            old = base_pids.get(pid)
            if old is None:
                continue
            if old.ppid != cur.ppid:
                delta.processes.reparented.append((cur, old.ppid, cur.ppid))
            if old.cmdline != cur.cmdline and cur.cmdline:
                delta.processes.cmdline_changed.append((cur, old.cmdline, cur.cmdline))

    def _diff_modules(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_keys = {m.key(): m for m in base.modules}
        cur_keys = {m.key(): m for m in current.modules}
        delta.modules.loaded = [cur_keys[k] for k in sorted(set(cur_keys) - set(base_keys))]
        delta.modules.unloaded = [base_keys[k] for k in sorted(set(base_keys) - set(cur_keys))]

    def _diff_network(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        def partition(items: list[NetworkSample]) -> tuple[dict[str, NetworkSample], dict[str, NetworkSample]]:
            listeners: dict[str, NetworkSample] = {}
            conns: dict[str, NetworkSample] = {}
            for item in items:
                if item.state == "LISTEN":
                    listeners[item.key()] = item
                else:
                    conns[item.key()] = item
            return listeners, conns

        base_l, base_c = partition(base.network)
        cur_l, cur_c = partition(current.network)
        delta.network.new_listeners = [cur_l[k] for k in sorted(set(cur_l) - set(base_l))]
        delta.network.closed_listeners = [base_l[k] for k in sorted(set(base_l) - set(cur_l))]
        delta.network.new_connections = [cur_c[k] for k in sorted(set(cur_c) - set(base_c))]
        delta.network.closed_connections = [base_c[k] for k in sorted(set(base_c) - set(cur_c))]

    def _diff_persistence(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_keys = {p.key(): p for p in base.persistence}
        cur_keys = {p.key(): p for p in current.persistence}
        delta.persistence.added = [cur_keys[k] for k in sorted(set(cur_keys) - set(base_keys))]
        delta.persistence.removed = [base_keys[k] for k in sorted(set(base_keys) - set(cur_keys))]

    def _diff_files(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_by_path = {f.path: f for f in base.critical_files}
        cur_by_path = {f.path: f for f in current.critical_files}
        delta.filesystem.added = [cur_by_path[p] for p in sorted(set(cur_by_path) - set(base_by_path))]
        delta.filesystem.removed = [base_by_path[p] for p in sorted(set(base_by_path) - set(cur_by_path))]
        for path in sorted(set(base_by_path) & set(cur_by_path)):
            if base_by_path[path].sha256 != cur_by_path[path].sha256:
                delta.filesystem.modified.append((base_by_path[path], cur_by_path[path]))

    def _diff_memory(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        if base.memory_digest is None or current.memory_digest is None:
            return
        base_digests = base.memory_digest.digests
        cur_digests = current.memory_digest.digests
        changed: list[int] = []
        new: list[int] = []
        removed: list[int] = []
        for offset, digest in cur_digests.items():
            if offset not in base_digests:
                new.append(offset)
            elif base_digests[offset] != digest:
                changed.append(offset)
        for offset in base_digests:
            if offset not in cur_digests:
                removed.append(offset)
        total = max(len(base_digests), len(cur_digests))
        delta.memory = MemoryPageDelta(
            changed_pages=sorted(changed),
            new_pages=sorted(new),
            removed_pages=sorted(removed),
            page_count=total,
        )

    def _diff_kernel_modules(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_set = set(base.kernel_modules)
        cur_set = set(current.kernel_modules)
        delta.kernel_modules.loaded = sorted(cur_set - base_set)
        delta.kernel_modules.unloaded = sorted(base_set - cur_set)

    def _diff_ebpf(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_set = set(base.ebpf_programs)
        cur_set = set(current.ebpf_programs)
        delta.ebpf_programs.loaded = sorted(cur_set - base_set)
        delta.ebpf_programs.unloaded = sorted(base_set - cur_set)

    def _diff_users(self, base: HostSnapshot, current: HostSnapshot, delta: SnapshotDelta) -> None:
        base_set = set(base.users)
        cur_set = set(current.users)
        delta.new_users = sorted(cur_set - base_set)
        delta.removed_users = sorted(base_set - cur_set)
