"""Host snapshot data model.

A ``HostSnapshot`` is an immutable point-in-time record of the forensically
relevant state of a host: its process tree, loaded modules, network
listeners, persistence artifacts, filesystem hashes of critical paths, and
(optionally) a page-level memory digest. Snapshots are the unit that the
baseline engine diffs to produce :class:`SnapshotDelta` objects.
"""
from __future__ import annotations

import hashlib
import os
import platform as _platform
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.detection.persistence.base import PersistenceArtifact

log = get_logger("baseline.snapshot")


# ---------------------------------------------------------------------------
# Sub-samples
# ---------------------------------------------------------------------------


class ProcessSample(BaseModel):
    pid: int
    ppid: int = 0
    comm: str = ""
    exe_path: str = ""
    cmdline: list[str] = Field(default_factory=list)
    uid: int = 0
    start_time_ns: int = 0
    exe_sha256: str = ""

    def key(self) -> str:
        return f"{self.pid}@{self.start_time_ns}"


class ModuleSample(BaseModel):
    name: str
    path: str = ""
    base_address: int = 0
    kind: str = "shared_lib"  # kernel_module | shared_lib | ebpf_program | driver
    sha256: str = ""
    owning_pid: int = 0

    def key(self) -> str:
        return f"{self.kind}:{self.name}@{self.owning_pid}"


class NetworkSample(BaseModel):
    protocol: str = "tcp"
    state: str = ""  # LISTEN | ESTABLISHED | ...
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    pid: int = 0

    def key(self) -> str:
        return f"{self.protocol}:{self.local_ip}:{self.local_port}->{self.remote_ip}:{self.remote_port}"


class FileSample(BaseModel):
    path: str
    sha256: str = ""
    size: int = 0
    mtime_ns: int = 0

    def key(self) -> str:
        return self.path


class PersistenceSample(BaseModel):
    mechanism: str
    location: str
    fingerprint: str
    mitre_technique: str = ""
    severity: str = ""

    def key(self) -> str:
        return self.fingerprint


class MemoryPageDigest(BaseModel):
    """A sparse page-level digest of a memory image.

    We hash each page and index by offset so a delta can detect which pages
    changed, were added, or removed. For very large images (16GB+) this is
    still cheap compared with a full byte diff.
    """

    page_size: int = 4096
    digests: dict[int, str] = Field(default_factory=dict)  # offset -> sha256 hex

    @classmethod
    def from_file(cls, path: Path, page_size: int = 4096) -> "MemoryPageDigest":
        digests: dict[int, str] = {}
        try:
            with path.open("rb") as fh:
                offset = 0
                while True:
                    chunk = fh.read(page_size)
                    if not chunk:
                        break
                    digests[offset] = hashlib.sha256(chunk).hexdigest()
                    offset += page_size
        except OSError as exc:
            log.debug("memory_digest_failed", path=str(path), error=str(exc))
        return cls(page_size=page_size, digests=digests)


# ---------------------------------------------------------------------------
# Host snapshot
# ---------------------------------------------------------------------------


class HostSnapshot(BaseModel):
    """An immutable snapshot of a host's forensic state at a point in time."""

    snapshot_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    host_id: str = "localhost"
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    platform: str = ""
    kernel: str = ""
    arch: str = ""

    processes: list[ProcessSample] = Field(default_factory=list)
    modules: list[ModuleSample] = Field(default_factory=list)
    network: list[NetworkSample] = Field(default_factory=list)
    persistence: list[PersistenceSample] = Field(default_factory=list)
    critical_files: list[FileSample] = Field(default_factory=list)
    kernel_modules: list[str] = Field(default_factory=list)
    ebpf_programs: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)

    memory_digest: MemoryPageDigest | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    @classmethod
    def capture_current(
        cls,
        *,
        host_id: str = "",
        critical_paths: list[Path] | None = None,
        include_memory: Path | None = None,
        include_persistence: bool = True,
        linux_root: Path | str = "/",
    ) -> "HostSnapshot":
        snap = cls(
            host_id=host_id or _platform.node() or "localhost",
            platform=_platform.system(),
            kernel=_platform.release(),
            arch=_platform.machine(),
        )
        snap.processes = _collect_processes()
        snap.network = _collect_network()
        snap.kernel_modules = _collect_kernel_modules()
        snap.ebpf_programs = _collect_ebpf_programs()
        snap.users = _collect_users()
        if critical_paths:
            snap.critical_files = _collect_files(critical_paths)
        if include_memory is not None and include_memory.is_file():
            snap.memory_digest = MemoryPageDigest.from_file(include_memory)
        if include_persistence:
            try:
                from deepview.detection.persistence.manager import PersistenceManager

                mgr = PersistenceManager(
                    context=None, linux_root=linux_root, macos_root=linux_root
                )
                persist_findings = mgr.scan(feed_correlation=False)
                snap.persistence = [
                    PersistenceSample(
                        mechanism=f.mechanism,
                        location=f.location,
                        fingerprint=f.fingerprint(),
                        mitre_technique=f.mitre_technique,
                        severity=f.severity.value,
                    )
                    for f in persist_findings
                ]
            except Exception:
                log.exception("persistence_capture_failed")
        return snap

    def process_keys(self) -> set[str]:
        return {p.key() for p in self.processes}

    def module_keys(self) -> set[str]:
        return {m.key() for m in self.modules}

    def network_keys(self) -> set[str]:
        return {n.key() for n in self.network}

    def persistence_keys(self) -> set[str]:
        return {p.key() for p in self.persistence}


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------


def _collect_processes() -> list[ProcessSample]:
    if sys.platform == "linux":
        return _linux_processes()
    if sys.platform == "darwin":
        return _darwin_processes()
    return []


def _linux_processes() -> list[ProcessSample]:
    procs: list[ProcessSample] = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return procs
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        try:
            cmdline_raw = (entry / "cmdline").read_bytes()
            cmdline = [
                s.decode("utf-8", "replace") for s in cmdline_raw.split(b"\x00") if s
            ]
        except OSError:
            cmdline = []
        try:
            exe = os.readlink(entry / "exe")
        except OSError:
            exe = ""
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace").split()
            start_ticks = int(stat[21])
        except (OSError, IndexError, ValueError):
            start_ticks = 0
        try:
            status = (entry / "status").read_text(encoding="utf-8", errors="replace")
            uid = 0
            ppid = 0
            for line in status.splitlines():
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
        except OSError:
            uid = 0
            ppid = 0
        procs.append(
            ProcessSample(
                pid=pid,
                ppid=ppid,
                comm=comm,
                exe_path=exe,
                cmdline=cmdline,
                uid=uid,
                start_time_ns=start_ticks,
            )
        )
    return procs


def _darwin_processes() -> list[ProcessSample]:
    """Best-effort process enum on macOS via ``ps``."""
    try:
        result = subprocess.run(
            ["ps", "-A", "-o", "pid=,ppid=,uid=,comm="],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except Exception:
        return []
    procs: list[ProcessSample] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid, ppid, uid, comm = int(parts[0]), int(parts[1]), int(parts[2]), parts[3]
        except ValueError:
            continue
        procs.append(
            ProcessSample(
                pid=pid,
                ppid=ppid,
                uid=uid,
                comm=comm,
                exe_path=comm,
            )
        )
    return procs


def _collect_network() -> list[NetworkSample]:
    if sys.platform == "linux":
        return _linux_network()
    if sys.platform == "darwin":
        return _darwin_network()
    return []


def _linux_network() -> list[NetworkSample]:
    samples: list[NetworkSample] = []
    for path, proto in (
        (Path("/proc/net/tcp"), "tcp"),
        (Path("/proc/net/tcp6"), "tcp6"),
        (Path("/proc/net/udp"), "udp"),
        (Path("/proc/net/udp6"), "udp6"),
    ):
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local = parts[1]
            remote = parts[2]
            state = parts[3]
            try:
                lip, lport = _parse_hex_endpoint(local)
                rip, rport = _parse_hex_endpoint(remote)
            except ValueError:
                continue
            samples.append(
                NetworkSample(
                    protocol=proto,
                    state=_tcp_state(state),
                    local_ip=lip,
                    local_port=lport,
                    remote_ip=rip,
                    remote_port=rport,
                )
            )
    return samples


def _parse_hex_endpoint(text: str) -> tuple[str, int]:
    ip, port = text.split(":")
    port_int = int(port, 16)
    if len(ip) == 8:
        ip_int = int(ip, 16)
        octets = [(ip_int >> (8 * i)) & 0xFF for i in range(4)]
        return ".".join(str(o) for o in octets), port_int
    # IPv6 rendered as 8 hex quartets; keep the raw form
    return ip, port_int


_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _tcp_state(code: str) -> str:
    return _TCP_STATES.get(code.upper(), code)


def _darwin_network() -> list[NetworkSample]:
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except Exception:
        return []
    samples: list[NetworkSample] = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proto = parts[7].lower()
        if proto not in ("tcp", "udp"):
            continue
        endpoint = parts[8]
        state = parts[9] if len(parts) > 9 else ""
        try:
            pid = int(parts[1])
        except ValueError:
            pid = 0
        if "->" in endpoint:
            local, remote = endpoint.split("->", 1)
        else:
            local, remote = endpoint, ""
        lip, lport = _split_hostport(local)
        rip, rport = _split_hostport(remote)
        samples.append(
            NetworkSample(
                protocol=proto,
                state=state.strip("()"),
                local_ip=lip,
                local_port=lport,
                remote_ip=rip,
                remote_port=rport,
                pid=pid,
            )
        )
    return samples


def _split_hostport(text: str) -> tuple[str, int]:
    if not text:
        return "", 0
    if ":" not in text:
        return text, 0
    host, _, port = text.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def _collect_kernel_modules() -> list[str]:
    if sys.platform != "linux":
        return []
    path = Path("/proc/modules")
    if not path.exists():
        return []
    try:
        return [line.split()[0] for line in path.read_text(encoding="utf-8").splitlines() if line]
    except OSError:
        return []


def _collect_ebpf_programs() -> list[str]:
    import shutil

    bpftool = shutil.which("bpftool")
    if bpftool is None:
        return []
    try:
        result = subprocess.run(
            [bpftool, "prog", "show", "-j"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except Exception:
        return []
    import json as _json

    try:
        data = _json.loads(result.stdout)
    except Exception:
        return []
    progs: list[str] = []
    for prog in data or []:
        name = str(prog.get("name") or prog.get("id") or "")
        if name:
            progs.append(name)
    return progs


def _collect_users() -> list[str]:
    users: set[str] = set()
    if sys.platform in ("linux", "darwin"):
        try:
            lines = Path("/etc/passwd").read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            parts = line.split(":")
            if parts:
                users.add(parts[0])
    return sorted(users)


def _collect_files(paths: list[Path]) -> list[FileSample]:
    samples: list[FileSample] = []
    for p in paths:
        try:
            data = p.read_bytes()
            stat = p.stat()
        except OSError:
            continue
        samples.append(
            FileSample(
                path=str(p),
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                mtime_ns=int(stat.st_mtime * 1e9),
            )
        )
    return samples
