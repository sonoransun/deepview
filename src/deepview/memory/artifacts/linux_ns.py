"""Linux namespace inventory extractor.

Flags processes whose pid/net/mnt/user/uts/ipc namespace diverges from
init (pid 1). Useful for spotting escape attempts and surfacing
container residents in a flat process listing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from deepview.tracing.linux import procfs


_NS_KINDS = ("pid", "net", "mnt", "user", "uts", "ipc", "cgroup", "time")


@dataclass(slots=True)
class NamespaceEntry:
    pid: int
    comm: str
    ns: dict[str, int] = field(default_factory=dict)
    diverges_from_init: list[str] = field(default_factory=list)


class LinuxNamespaceInventory:
    def extract(self) -> Iterator[NamespaceEntry]:
        init = procfs.read_process(1)
        baseline = dict(init.ns) if init is not None else {}
        for rec in procfs.iter_processes():
            diverges = [k for k in _NS_KINDS if baseline.get(k) != rec.ns.get(k) and rec.ns.get(k)]
            yield NamespaceEntry(
                pid=rec.pid,
                comm=rec.comm,
                ns=dict(rec.ns),
                diverges_from_init=diverges,
            )
