"""Linux namespace inventory — surfaces containerised processes."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="linux_ns",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Namespace inventory: pid/net/mnt/user/uts/ipc/cgroup per process, flagging divergence from init",
    tags=["linux", "namespace", "container", "live"],
)
class LinuxNamespacePlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="only_divergent",
                description="Only show processes whose namespaces diverge from init",
                required=False,
                default=False,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.memory.artifacts.linux_ns import LinuxNamespaceInventory

        only_divergent = bool(self.config.get("only_divergent", False))
        rows = []
        for entry in LinuxNamespaceInventory().extract():
            if only_divergent and not entry.diverges_from_init:
                continue
            rows.append({
                "PID": str(entry.pid),
                "Comm": entry.comm,
                "pid_ns": str(entry.ns.get("pid", 0)),
                "net_ns": str(entry.ns.get("net", 0)),
                "mnt_ns": str(entry.ns.get("mnt", 0)),
                "user_ns": str(entry.ns.get("user", 0)),
                "Diverges": ",".join(entry.diverges_from_init),
            })
        return PluginResult(
            columns=["PID", "Comm", "pid_ns", "net_ns", "mnt_ns", "user_ns", "Diverges"],
            rows=rows,
        )
