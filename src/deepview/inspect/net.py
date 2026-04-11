"""On-demand network inspector."""
from __future__ import annotations

from deepview.interfaces.plugin import PluginResult
from deepview.tracing.linux import netlink, procfs


class NetInspector:
    """Cross-reference /proc/net sockets with optional netlink info."""

    def __init__(self, pid: int | None = None) -> None:
        self._pid = pid

    def to_plugin_result(self) -> PluginResult:
        sockets = procfs.enrich_sockets_with_pids(procfs.iter_sockets())
        if self._pid is not None:
            sockets = [s for s in sockets if s.pid == self._pid]
        rows = []
        for s in sockets:
            rows.append({
                "Proto": s.proto,
                "Local": f"{s.local_ip}:{s.local_port}",
                "Remote": f"{s.remote_ip}:{s.remote_port}",
                "State": s.state,
                "UID": str(s.uid),
                "PID": str(s.pid),
                "Comm": s.comm,
            })
        metadata = {}
        if netlink.available():
            metadata["interfaces"] = [
                {
                    "name": i.name,
                    "state": i.state,
                    "addresses": i.addresses,
                }
                for i in netlink.list_interfaces()
            ]
        return PluginResult(
            columns=["Proto", "Local", "Remote", "State", "UID", "PID", "Comm"],
            rows=rows,
            metadata=metadata,
        )
