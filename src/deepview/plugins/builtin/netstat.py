"""Network connection listing plugin."""
from __future__ import annotations
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

@register_plugin(
    name="netstat",
    category=PluginCategory.NETWORK_ANALYSIS,
    description="List network connections from a memory image",
    tags=["network", "connections", "memory"],
)
class NetstatPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(name="engine", description="Analysis engine", required=False, default="auto"),
        ]

    def run(self) -> PluginResult:
        return PluginResult(
            columns=["Proto", "LocalAddr", "LocalPort", "RemoteAddr", "RemotePort", "State", "PID", "Process"],
            rows=[],
            metadata={"note": "Requires memory image with network structures"},
        )
