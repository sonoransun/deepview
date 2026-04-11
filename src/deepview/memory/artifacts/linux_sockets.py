"""Linux live socket table extractor with pid/comm attribution."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from deepview.tracing.linux import procfs


@dataclass(slots=True)
class SocketEntry:
    proto: str
    local: str
    remote: str
    state: str
    uid: int
    pid: int
    comm: str
    inode: int


class LinuxSocketTable:
    def extract(self) -> Iterator[SocketEntry]:
        sockets = procfs.enrich_sockets_with_pids(procfs.iter_sockets())
        for s in sockets:
            yield SocketEntry(
                proto=s.proto,
                local=f"{s.local_ip}:{s.local_port}" if s.local_ip else f":{s.local_port}",
                remote=f"{s.remote_ip}:{s.remote_port}" if s.remote_ip else f":{s.remote_port}",
                state=s.state,
                uid=s.uid,
                pid=s.pid,
                comm=s.comm,
                inode=s.inode,
            )
