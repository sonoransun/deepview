"""Stdlib-only ``/proc`` and ``/sys`` enumeration for Linux forensics.

This module is the workhorse for Linux-native visibility on a live host.
It parses ``/proc/[pid]/*`` and ``/proc/net/*`` files into typed
dataclasses and exposes a :class:`ProcfsPoller` that periodically
snapshots the host and publishes :class:`MonitorEvent`s into a
:class:`TraceEventBus`.

Nothing here imports a third-party package: every helper works on any
Linux box with a mounted procfs, and callers running on non-Linux
platforms will simply see empty results (we never raise at import time).

The data classes are plain ``@dataclass(slots=True)`` records so they
survive JSON serialisation into the replay store without pydantic.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import TraceEventBus

log = get_logger("tracing.linux.procfs")


_PROC = Path("/proc")
_SYS = Path("/sys")


# ---------------------------------------------------------------------------
# Typed snapshots
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ProcessRecord:
    """Point-in-time view of one ``/proc/[pid]``."""

    pid: int
    ppid: int = 0
    tgid: int = 0
    uid: int = 0
    gid: int = 0
    euid: int = 0
    egid: int = 0
    loginuid: int = -1
    comm: str = ""
    state: str = ""
    cmdline: str = ""
    exe: str = ""
    cwd: str = ""
    root: str = ""
    cgroup: str = ""
    ns: dict[str, int] = field(default_factory=dict)
    fds: int = 0
    threads: int = 0
    rss_kb: int = 0
    vm_kb: int = 0
    starttime_ticks: int = 0
    capabilities_eff: int = 0

    def as_process_context(self) -> ProcessContext:
        return ProcessContext(
            pid=self.pid,
            tid=self.pid,
            ppid=self.ppid,
            uid=self.uid,
            gid=self.gid,
            comm=self.comm,
            exe_path=self.exe,
            cgroup=self.cgroup,
        )


@dataclass(slots=True)
class SocketRecord:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    uid: int
    inode: int
    pid: int = 0
    comm: str = ""


@dataclass(slots=True)
class ModuleRecord:
    name: str
    size: int
    refcount: int
    deps: list[str] = field(default_factory=list)
    state: str = "Live"
    address: int = 0
    taints: str = ""


@dataclass(slots=True)
class MountRecord:
    source: str
    target: str
    fstype: str
    options: str
    mount_id: int = 0
    parent_id: int = 0
    propagation: str = ""


@dataclass(slots=True)
class KernelTaint:
    value: int
    flags: list[str]
    modules_disabled: bool
    ptrace_scope: int


# ---------------------------------------------------------------------------
# /proc/[pid] parsers
# ---------------------------------------------------------------------------


def _read_text(path: Path, limit: int = 65536) -> str:
    try:
        with path.open("rb") as f:
            return f.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _read_bytes(path: Path, limit: int = 65536) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _parse_status(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def _pid_dirs() -> Iterator[int]:
    if not _PROC.exists():
        return
    for entry in _PROC.iterdir():
        name = entry.name
        if name.isdigit():
            try:
                yield int(name)
            except ValueError:
                continue


def read_process(pid: int) -> Optional[ProcessRecord]:
    """Parse one ``/proc/[pid]`` directory into a :class:`ProcessRecord`.

    Returns ``None`` if the pid has gone away or cannot be read. All
    fields degrade gracefully to defaults — missing permissions (common
    for non-root on other users' processes) yield partial records
    rather than exceptions.
    """
    base = _PROC / str(pid)
    if not base.exists():
        return None

    status_text = _read_text(base / "status")
    if not status_text:
        return None

    st = _parse_status(status_text)

    def _int(key: str, default: int = 0) -> int:
        try:
            return int(st.get(key, "").split()[0])
        except (ValueError, IndexError):
            return default

    uids = st.get("Uid", "0 0 0 0").split()
    gids = st.get("Gid", "0 0 0 0").split()

    def _pick(vals: list[str], idx: int) -> int:
        try:
            return int(vals[idx])
        except (ValueError, IndexError):
            return 0

    record = ProcessRecord(
        pid=pid,
        ppid=_int("PPid"),
        tgid=_int("Tgid"),
        uid=_pick(uids, 0),
        euid=_pick(uids, 1),
        gid=_pick(gids, 0),
        egid=_pick(gids, 1),
        comm=st.get("Name", ""),
        state=st.get("State", "").split()[0] if st.get("State") else "",
        threads=_int("Threads"),
        rss_kb=_int("VmRSS"),
        vm_kb=_int("VmSize"),
    )

    record.cmdline = _read_bytes(base / "cmdline", 4096).replace(b"\x00", b" ").decode(
        "utf-8", errors="replace"
    ).strip()
    record.exe = _safe_readlink(base / "exe")
    record.cwd = _safe_readlink(base / "cwd")
    record.root = _safe_readlink(base / "root")
    record.cgroup = _read_text(base / "cgroup", 4096).strip()

    loginuid_text = _read_text(base / "loginuid", 32).strip()
    if loginuid_text.isdigit() or (loginuid_text.startswith("-") and loginuid_text[1:].isdigit()):
        record.loginuid = int(loginuid_text)

    # Namespace inodes.
    ns_dir = base / "ns"
    if ns_dir.is_dir():
        for name in ("pid", "net", "mnt", "user", "uts", "ipc", "cgroup", "time"):
            try:
                target = os.readlink(ns_dir / name)
                # e.g. "pid:[4026531836]"
                inode_str = target.split("[", 1)[-1].rstrip("]")
                record.ns[name] = int(inode_str)
            except (OSError, ValueError):
                continue

    # Open fd count.
    fd_dir = base / "fd"
    try:
        record.fds = sum(1 for _ in fd_dir.iterdir())
    except OSError:
        record.fds = 0

    # /proc/[pid]/stat: starttime is field 22 (0-indexed 21).
    stat_text = _read_text(base / "stat", 4096)
    # Format: pid (comm) state ppid ... — comm may contain spaces/parens.
    if stat_text:
        try:
            rparen = stat_text.rfind(")")
            after = stat_text[rparen + 2 :].split()
            if len(after) >= 20:
                record.starttime_ticks = int(after[19])
        except (ValueError, IndexError):
            pass

    # Effective capabilities.
    cap_eff = st.get("CapEff", "")
    if cap_eff:
        try:
            record.capabilities_eff = int(cap_eff, 16)
        except ValueError:
            pass

    return record


def _safe_readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def iter_processes() -> Iterator[ProcessRecord]:
    for pid in _pid_dirs():
        rec = read_process(pid)
        if rec is not None:
            yield rec


# ---------------------------------------------------------------------------
# /proc/net/{tcp,tcp6,udp,udp6,unix}
# ---------------------------------------------------------------------------


_TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}


def _ip_port_from_hex(token: str, v6: bool) -> tuple[str, int]:
    try:
        ip_hex, port_hex = token.split(":")
        port = int(port_hex, 16)
    except ValueError:
        return "", 0
    if v6:
        if len(ip_hex) != 32:
            return "", port
        raw = bytes.fromhex(ip_hex)
        # /proc encodes IPv6 in host byte order per 32-bit word; swap.
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        packed = b"".join(words)
        try:
            return socket.inet_ntop(socket.AF_INET6, packed), port
        except OSError:
            return "", port
    else:
        if len(ip_hex) != 8:
            return "", port
        raw = bytes.fromhex(ip_hex)[::-1]
        try:
            return socket.inet_ntop(socket.AF_INET, raw), port
        except OSError:
            return "", port


def _iter_proc_net(path: Path, proto: str, v6: bool) -> Iterator[SocketRecord]:
    text = _read_text(path)
    if not text:
        return
    lines = text.splitlines()
    if len(lines) < 2:
        return
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        remote = parts[2]
        try:
            state_code = int(parts[3], 16)
        except ValueError:
            state_code = 0
        try:
            uid = int(parts[7])
        except ValueError:
            uid = 0
        try:
            inode = int(parts[9])
        except ValueError:
            inode = 0
        lip, lport = _ip_port_from_hex(local, v6)
        rip, rport = _ip_port_from_hex(remote, v6)
        yield SocketRecord(
            proto=proto,
            local_ip=lip,
            local_port=lport,
            remote_ip=rip,
            remote_port=rport,
            state=_TCP_STATES.get(state_code, str(state_code)),
            uid=uid,
            inode=inode,
        )


def iter_sockets() -> Iterator[SocketRecord]:
    """Enumerate TCP, TCP6, UDP, UDP6 sockets from ``/proc/net``."""
    yield from _iter_proc_net(_PROC / "net" / "tcp", "tcp", False)
    yield from _iter_proc_net(_PROC / "net" / "tcp6", "tcp6", True)
    yield from _iter_proc_net(_PROC / "net" / "udp", "udp", False)
    yield from _iter_proc_net(_PROC / "net" / "udp6", "udp6", True)


def build_socket_inode_index() -> dict[int, tuple[int, str]]:
    """Map socket inode → (pid, comm) by scanning every ``/proc/[pid]/fd``.

    Best-effort: entries for processes we cannot read are silently
    skipped. Only sockets (links starting with ``socket:``) contribute.
    """
    out: dict[int, tuple[int, str]] = {}
    for pid in _pid_dirs():
        fd_dir = _PROC / str(pid) / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            continue
        comm = _read_text(_PROC / str(pid) / "comm").strip()
        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            out.setdefault(inode, (pid, comm))
    return out


def enrich_sockets_with_pids(records: Iterable[SocketRecord]) -> list[SocketRecord]:
    index = build_socket_inode_index()
    enriched: list[SocketRecord] = []
    for rec in records:
        if rec.inode and rec.inode in index:
            rec.pid, rec.comm = index[rec.inode]
        enriched.append(rec)
    return enriched


# ---------------------------------------------------------------------------
# /proc/modules and /proc/mounts
# ---------------------------------------------------------------------------


def iter_modules() -> Iterator[ModuleRecord]:
    text = _read_text(_PROC / "modules")
    if not text:
        return
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[0]
        try:
            size = int(parts[1])
        except ValueError:
            size = 0
        try:
            refcount = int(parts[2])
        except ValueError:
            refcount = 0
        deps = [d for d in parts[3].split(",") if d and d != "-"]
        state = parts[4] if len(parts) > 4 else "Live"
        address = 0
        if len(parts) > 5:
            try:
                address = int(parts[5], 16)
            except ValueError:
                address = 0
        taints = parts[6] if len(parts) > 6 else ""
        yield ModuleRecord(
            name=name,
            size=size,
            refcount=refcount,
            deps=deps,
            state=state,
            address=address,
            taints=taints,
        )


def iter_mounts() -> Iterator[MountRecord]:
    # Prefer /proc/self/mountinfo (richer), fall back to /proc/mounts.
    text = _read_text(_PROC / "self" / "mountinfo")
    if text:
        for line in text.splitlines():
            parts = line.split(" - ")
            if len(parts) != 2:
                continue
            left = parts[0].split()
            right = parts[1].split()
            if len(left) < 6 or len(right) < 3:
                continue
            try:
                mount_id = int(left[0])
                parent_id = int(left[1])
            except ValueError:
                mount_id = parent_id = 0
            propagation = " ".join(left[6:]) if len(left) > 6 else ""
            yield MountRecord(
                source=right[1],
                target=left[4],
                fstype=right[0],
                options=right[2],
                mount_id=mount_id,
                parent_id=parent_id,
                propagation=propagation,
            )
        return
    text = _read_text(_PROC / "mounts")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        yield MountRecord(source=parts[0], target=parts[1], fstype=parts[2], options=parts[3])


def read_kernel_taint() -> KernelTaint:
    text = _read_text(_PROC / "sys" / "kernel" / "tainted").strip()
    try:
        value = int(text)
    except ValueError:
        value = 0
    flags = _decode_taint_flags(value)
    modules_disabled = _read_text(_PROC / "sys" / "kernel" / "modules_disabled").strip() == "1"
    try:
        ptrace_scope = int(_read_text(_PROC / "sys" / "kernel" / "yama" / "ptrace_scope").strip())
    except ValueError:
        ptrace_scope = 0
    return KernelTaint(
        value=value, flags=flags, modules_disabled=modules_disabled, ptrace_scope=ptrace_scope
    )


_TAINT_BITS = [
    (0, "PROPRIETARY_MODULE"),
    (1, "FORCED_MODULE"),
    (2, "UNSAFE_SMP"),
    (3, "FORCED_RMMOD"),
    (4, "MACHINE_CHECK"),
    (5, "BAD_PAGE"),
    (6, "USER"),
    (7, "DIE"),
    (8, "OVERRIDDEN_ACPI"),
    (9, "WARN"),
    (10, "CRAP"),
    (11, "FIRMWARE_WORKAROUND"),
    (12, "OOT_MODULE"),
    (13, "UNSIGNED_MODULE"),
    (14, "SOFTLOCKUP"),
    (15, "LIVE_PATCH"),
    (16, "AUX"),
    (17, "RANDSTRUCT"),
    (18, "TEST"),
]


def _decode_taint_flags(value: int) -> list[str]:
    return [name for bit, name in _TAINT_BITS if value & (1 << bit)]


# ---------------------------------------------------------------------------
# ProcfsPoller — periodic publisher into a TraceEventBus
# ---------------------------------------------------------------------------


class ProcfsPoller:
    """Background thread that snapshots ``/proc`` and publishes events.

    On every tick the poller walks the process list, diffs it against
    the previous tick, and publishes ``MonitorEvent``s for new and
    exited pids. It also snapshots kernel modules and sockets on
    request via :meth:`snapshot_full`. The poller never raises on
    procfs errors; it logs them and continues.
    """

    def __init__(
        self,
        bus: TraceEventBus,
        *,
        interval_s: float = 2.0,
        include_existing: bool = False,
    ) -> None:
        self._bus = bus
        self._interval_s = interval_s
        self._include_existing = include_existing
        self._thread: threading.Thread | None = None
        self._running = False
        self._seen_pids: set[int] = set()
        self._last_modules: set[str] = set()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="procfs-poller")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=self._interval_s * 2)

    @property
    def is_running(self) -> bool:
        return self._running

    def _run(self) -> None:
        while self._running:
            try:
                self._tick()
            except Exception as e:  # noqa: BLE001 - never crash the poller
                log.warning("procfs_tick_error", error=str(e))
            time.sleep(self._interval_s)

    def _tick(self) -> None:
        seen_now: set[int] = set()
        for rec in iter_processes():
            seen_now.add(rec.pid)
            if rec.pid in self._seen_pids:
                continue
            if self._seen_pids or self._include_existing:
                self._publish_process(rec, kind="proc_new")
        for gone in self._seen_pids - seen_now:
            self._publish_exit(gone)
        self._seen_pids = seen_now

        modules_now: set[str] = {m.name for m in iter_modules()}
        if self._last_modules:
            for new in modules_now - self._last_modules:
                self._publish_module(new, kind="module_loaded")
            for removed in self._last_modules - modules_now:
                self._publish_module(removed, kind="module_unloaded")
        self._last_modules = modules_now

    def _publish_process(self, rec: ProcessRecord, *, kind: str) -> None:
        ev = MonitorEvent(
            timestamp_ns=time.monotonic_ns(),
            wall_clock_ns=time.time_ns(),
            category=EventCategory.PROCESS,
            severity=EventSeverity.INFO,
            source=EventSource(platform="linux", backend="procfs", probe_name=kind),
            process=rec.as_process_context(),
            syscall_name=kind,
            args={
                "cmdline": rec.cmdline,
                "exe": rec.exe,
                "cwd": rec.cwd,
                "state": rec.state,
                "threads": rec.threads,
                "fds": rec.fds,
                "ns": rec.ns,
                "cgroup": rec.cgroup,
            },
        )
        self._bus.publish_sync(ev)

    def _publish_exit(self, pid: int) -> None:
        ev = MonitorEvent(
            timestamp_ns=time.monotonic_ns(),
            wall_clock_ns=time.time_ns(),
            category=EventCategory.PROCESS,
            severity=EventSeverity.INFO,
            source=EventSource(platform="linux", backend="procfs", probe_name="proc_exit"),
            process=ProcessContext(pid=pid, tid=pid, ppid=0, uid=0, gid=0, comm=""),
            syscall_name="proc_exit",
        )
        self._bus.publish_sync(ev)

    def _publish_module(self, name: str, *, kind: str) -> None:
        ev = MonitorEvent(
            timestamp_ns=time.monotonic_ns(),
            wall_clock_ns=time.time_ns(),
            category=EventCategory.MODULE,
            severity=EventSeverity.WARNING if kind == "module_loaded" else EventSeverity.INFO,
            source=EventSource(platform="linux", backend="procfs", probe_name=kind),
            process=None,
            syscall_name=kind,
            args={"module": name},
        )
        self._bus.publish_sync(ev)

    def snapshot_full(self) -> dict:
        """Return a full ``/proc`` snapshot as a JSON-serialisable dict.

        Used by the replay recorder and on-demand inspector. The output
        intentionally omits binary fields and truncates long strings
        so snapshots stay bounded for the session store.
        """
        return {
            "ts_ns": time.time_ns(),
            "processes": [
                {
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "uid": p.uid,
                    "comm": p.comm,
                    "cmdline": p.cmdline[:1024],
                    "exe": p.exe,
                    "state": p.state,
                    "ns": p.ns,
                    "cgroup": p.cgroup[:256],
                    "fds": p.fds,
                    "threads": p.threads,
                }
                for p in iter_processes()
            ],
            "sockets": [
                {
                    "proto": s.proto,
                    "local": f"{s.local_ip}:{s.local_port}",
                    "remote": f"{s.remote_ip}:{s.remote_port}",
                    "state": s.state,
                    "uid": s.uid,
                    "inode": s.inode,
                }
                for s in iter_sockets()
            ],
            "modules": [
                {"name": m.name, "size": m.size, "refcount": m.refcount, "taints": m.taints}
                for m in iter_modules()
            ],
            "mounts": [
                {
                    "source": mt.source,
                    "target": mt.target,
                    "fstype": mt.fstype,
                    "options": mt.options,
                }
                for mt in iter_mounts()
            ],
            "kernel_taint": _kernel_taint_dict(),
        }


def _kernel_taint_dict() -> dict:
    taint = read_kernel_taint()
    return {
        "value": taint.value,
        "flags": list(taint.flags),
        "modules_disabled": taint.modules_disabled,
        "ptrace_scope": taint.ptrace_scope,
    }
