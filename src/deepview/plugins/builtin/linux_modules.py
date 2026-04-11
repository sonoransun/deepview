"""Linux loaded kernel modules from /proc/modules."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="linux_modules",
    category=PluginCategory.ROOTKIT_DETECTION,
    description="Loaded kernel modules with address, refcount, dependencies and taint flags",
    tags=["linux", "kernel", "module", "rootkit"],
)
class LinuxModulesPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return []

    def run(self) -> PluginResult:
        from deepview.tracing.linux import procfs

        rows = []
        for m in procfs.iter_modules():
            rows.append({
                "Name": m.name,
                "Size": str(m.size),
                "Refs": str(m.refcount),
                "Deps": ",".join(m.deps),
                "State": m.state,
                "Address": f"0x{m.address:x}" if m.address else "",
                "Taints": m.taints,
            })
        return PluginResult(
            columns=["Name", "Size", "Refs", "Deps", "State", "Address", "Taints"],
            rows=rows,
        )
