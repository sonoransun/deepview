"""Linux ``/proc`` snapshot extractor.

Unlike the memory-dump artifact extractors in this package, this one
sources from a live ``/proc`` filesystem via
:mod:`deepview.tracing.linux.procfs`. It follows the same shape (an
extractor class returning typed entries) so callers can use either
kind interchangeably from a plugin.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from deepview.core.logging import get_logger
from deepview.tracing.linux import procfs

log = get_logger("memory.artifacts.linux_proc")


@dataclass(slots=True)
class LinuxProcessEntry:
    pid: int
    ppid: int
    uid: int
    comm: str
    state: str
    exe: str
    cmdline: str
    threads: int
    fds: int
    rss_kb: int
    cgroup: str
    pid_ns: int = 0
    net_ns: int = 0
    mnt_ns: int = 0


class LinuxProcSnapshot:
    """Enumerate live processes from ``/proc``."""

    def extract(self) -> Iterator[LinuxProcessEntry]:
        for rec in procfs.iter_processes():
            yield LinuxProcessEntry(
                pid=rec.pid,
                ppid=rec.ppid,
                uid=rec.uid,
                comm=rec.comm,
                state=rec.state,
                exe=rec.exe,
                cmdline=rec.cmdline,
                threads=rec.threads,
                fds=rec.fds,
                rss_kb=rec.rss_kb,
                cgroup=rec.cgroup.splitlines()[0] if rec.cgroup else "",
                pid_ns=rec.ns.get("pid", 0),
                net_ns=rec.ns.get("net", 0),
                mnt_ns=rec.ns.get("mnt", 0),
            )
