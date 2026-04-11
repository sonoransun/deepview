"""Linux live process listing via /proc (no memory image required)."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="linux_proc",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Live Linux process listing from /proc with namespace and cgroup info",
    tags=["linux", "proc", "live", "process"],
)
class LinuxProcPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="limit",
                description="Max processes to return (default 1000)",
                required=False,
                default=1000,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.memory.artifacts.linux_proc import LinuxProcSnapshot

        try:
            limit = int(self.config.get("limit", 1000))
        except (TypeError, ValueError):
            limit = 1000

        snap = LinuxProcSnapshot()
        rows = []
        total = 0
        for entry in snap.extract():
            total += 1
            if len(rows) >= limit:
                continue
            rows.append({
                "PID": str(entry.pid),
                "PPID": str(entry.ppid),
                "UID": str(entry.uid),
                "Comm": entry.comm,
                "State": entry.state,
                "Threads": str(entry.threads),
                "FDs": str(entry.fds),
                "RSS(KB)": str(entry.rss_kb),
                "Exe": entry.exe,
                "Cmdline": entry.cmdline[:120],
            })

        return PluginResult(
            columns=["PID", "PPID", "UID", "Comm", "State", "Threads", "FDs", "RSS(KB)", "Exe", "Cmdline"],
            rows=rows,
            metadata={"total_found": total, "limit": limit},
        )
