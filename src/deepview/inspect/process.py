"""On-demand process inspector.

Given a live PID (and optionally a session snapshot timestamp), this
inspector returns a rich bundle covering status, cmdline, env, maps,
open fds, loaded libraries, network sockets, and namespaces. Output
is a :class:`~deepview.interfaces.plugin.PluginResult` so the
existing formatters render it identically to a memory-dump plugin.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from deepview.interfaces.plugin import PluginResult
from deepview.tracing.linux import procfs


@dataclass
class ProcessSnapshot:
    pid: int
    status: dict[str, str]
    cmdline: str
    environ: list[str]
    exe: str
    cwd: str
    maps: list[dict[str, Any]]
    fds: list[dict[str, Any]]
    threads: list[int]
    namespaces: dict[str, int]
    sockets: list[dict[str, Any]]
    loaded_libraries: list[str]


class ProcessInspector:
    """Produce a full on-demand snapshot of a live process."""

    def __init__(self, pid: int) -> None:
        self._pid = pid

    def capture(self) -> ProcessSnapshot:
        rec = procfs.read_process(self._pid)
        if rec is None:
            raise ProcessLookupError(f"pid {self._pid} not found or unreadable")
        base = Path(f"/proc/{self._pid}")

        environ = self._read_environ(base)
        maps = self._read_maps(base)
        fds = self._read_fds(base)
        threads = self._read_threads(base)
        libs = sorted({m["pathname"] for m in maps if m["pathname"].endswith((".so", ".so.1", ".so.2", ".so.3")) or ".so." in m["pathname"]})
        sockets = self._process_sockets(rec.pid)

        return ProcessSnapshot(
            pid=rec.pid,
            status={
                "Name": rec.comm,
                "State": rec.state,
                "Ppid": str(rec.ppid),
                "Uid": str(rec.uid),
                "Gid": str(rec.gid),
                "Threads": str(rec.threads),
                "RSS_KB": str(rec.rss_kb),
                "VM_KB": str(rec.vm_kb),
                "LoginUid": str(rec.loginuid),
                "CapEff": f"0x{rec.capabilities_eff:016x}",
            },
            cmdline=rec.cmdline,
            environ=environ,
            exe=rec.exe,
            cwd=rec.cwd,
            maps=maps,
            fds=fds,
            threads=threads,
            namespaces=dict(rec.ns),
            sockets=sockets,
            loaded_libraries=libs,
        )

    def to_plugin_result(self) -> PluginResult:
        try:
            snap = self.capture()
        except ProcessLookupError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        rows: list[dict] = []
        for k, v in snap.status.items():
            rows.append({"Key": k, "Value": v})
        rows.append({"Key": "Exe", "Value": snap.exe})
        rows.append({"Key": "Cwd", "Value": snap.cwd})
        rows.append({"Key": "Cmdline", "Value": snap.cmdline[:200]})
        rows.append({"Key": "EnvCount", "Value": str(len(snap.environ))})
        rows.append({"Key": "Maps", "Value": str(len(snap.maps))})
        rows.append({"Key": "Fds", "Value": str(len(snap.fds))})
        rows.append({"Key": "Threads", "Value": str(len(snap.threads))})
        rows.append({"Key": "Sockets", "Value": str(len(snap.sockets))})
        rows.append({"Key": "Libraries", "Value": str(len(snap.loaded_libraries))})
        for ns, inode in snap.namespaces.items():
            rows.append({"Key": f"ns.{ns}", "Value": str(inode)})

        return PluginResult(
            columns=["Key", "Value"],
            rows=rows,
            metadata={
                "maps_sample": snap.maps[:20],
                "fds_sample": snap.fds[:20],
                "libraries": snap.loaded_libraries[:40],
                "environ_sample": snap.environ[:20],
                "sockets_sample": snap.sockets[:20],
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_environ(self, base: Path) -> list[str]:
        try:
            with (base / "environ").open("rb") as f:
                raw = f.read(65536)
        except OSError:
            return []
        return [v.decode("utf-8", errors="replace") for v in raw.split(b"\x00") if v]

    def _read_maps(self, base: Path) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with (base / "maps").open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split(maxsplit=5)
                    if len(parts) < 5:
                        continue
                    addrs = parts[0].split("-")
                    if len(addrs) != 2:
                        continue
                    try:
                        start = int(addrs[0], 16)
                        end = int(addrs[1], 16)
                    except ValueError:
                        continue
                    out.append({
                        "start": f"0x{start:x}",
                        "end": f"0x{end:x}",
                        "size": end - start,
                        "perms": parts[1],
                        "pathname": parts[5].strip() if len(parts) > 5 else "",
                    })
        except OSError:
            pass
        return out

    def _read_fds(self, base: Path) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        fd_dir = base / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            return out
        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            kind = "file"
            if target.startswith("socket:"):
                kind = "socket"
            elif target.startswith("pipe:"):
                kind = "pipe"
            elif target.startswith("anon_inode:"):
                kind = "anon"
            out.append({"fd": entry.name, "kind": kind, "target": target})
        return out

    def _read_threads(self, base: Path) -> list[int]:
        try:
            return sorted(int(d.name) for d in (base / "task").iterdir() if d.name.isdigit())
        except OSError:
            return []

    def _process_sockets(self, pid: int) -> list[dict[str, Any]]:
        # Reuse the live socket table by filtering inodes we hold open.
        fd_dir = Path(f"/proc/{pid}/fd")
        inodes: set[int] = set()
        try:
            for entry in fd_dir.iterdir():
                try:
                    target = os.readlink(entry)
                except OSError:
                    continue
                if target.startswith("socket:["):
                    try:
                        inodes.add(int(target[8:-1]))
                    except ValueError:
                        continue
        except OSError:
            return []
        if not inodes:
            return []
        out: list[dict[str, Any]] = []
        for s in procfs.iter_sockets():
            if s.inode in inodes:
                out.append({
                    "proto": s.proto,
                    "local": f"{s.local_ip}:{s.local_port}",
                    "remote": f"{s.remote_ip}:{s.remote_port}",
                    "state": s.state,
                })
        return out
