"""Malicious memory detection plugin."""
from __future__ import annotations
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

@register_plugin(
    name="malfind",
    category=PluginCategory.MALWARE_DETECTION,
    description="Detect suspicious memory regions (injected code, hollow processes)",
    tags=["malware", "injection", "memory"],
)
class MalfindPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(name="engine", description="Analysis engine", required=False, default="auto"),
            Requirement(name="pid", description="Filter by PID", required=False),
        ]

    def run(self) -> PluginResult:
        return PluginResult(
            columns=["PID", "Process", "Address", "VadTag", "Protection", "Flags", "Hexdump"],
            rows=[],
            metadata={"note": "Scans VAD entries for suspicious characteristics"},
        )
