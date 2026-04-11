"""Linux live socket table from /proc/net with PID/comm attribution."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="linux_netstat",
    category=PluginCategory.NETWORK_FORENSICS,
    description="Live TCP/UDP socket listing from /proc/net with inode→pid attribution",
    tags=["linux", "netstat", "live", "network"],
)
class LinuxNetstatPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="state",
                description="Filter by TCP state (e.g. LISTEN, ESTABLISHED)",
                required=False,
                default=None,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.memory.artifacts.linux_sockets import LinuxSocketTable

        state_filter = self.config.get("state")
        rows = []
        total = 0
        for s in LinuxSocketTable().extract():
            total += 1
            if state_filter and s.state != state_filter:
                continue
            rows.append({
                "Proto": s.proto,
                "Local": s.local,
                "Remote": s.remote,
                "State": s.state,
                "UID": str(s.uid),
                "PID": str(s.pid) if s.pid else "",
                "Comm": s.comm,
            })
        return PluginResult(
            columns=["Proto", "Local", "Remote", "State", "UID", "PID", "Comm"],
            rows=rows,
            metadata={"total_found": total},
        )
