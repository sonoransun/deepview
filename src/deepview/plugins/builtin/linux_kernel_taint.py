"""Linux kernel taint + ptrace_scope summary."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="linux_kernel_taint",
    category=PluginCategory.ROOTKIT_DETECTION,
    description="Kernel taint bits, modules_disabled, and Yama ptrace_scope in one sheet",
    tags=["linux", "kernel", "taint", "hardening"],
)
class LinuxKernelTaintPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return []

    def run(self) -> PluginResult:
        from deepview.tracing.linux import procfs

        taint = procfs.read_kernel_taint()
        rows = [
            {"Key": "taint_value", "Value": str(taint.value)},
            {"Key": "taint_flags", "Value": ",".join(taint.flags) or "(none)"},
            {"Key": "modules_disabled", "Value": str(taint.modules_disabled)},
            {"Key": "ptrace_scope", "Value": str(taint.ptrace_scope)},
        ]
        return PluginResult(columns=["Key", "Value"], rows=rows)
