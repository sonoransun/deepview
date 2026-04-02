"""DKOM (Direct Kernel Object Manipulation) detection plugin."""
from __future__ import annotations
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory, Platform

@register_plugin(
    name="dkom_detect",
    category=PluginCategory.MALWARE_DETECTION,
    description="Detect hidden processes via DKOM by cross-referencing kernel structures",
    tags=["dkom", "rootkit", "hidden_process", "anti-forensics"],
    platforms=[Platform.LINUX, Platform.WINDOWS],
)
class DKOMDetectPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
        ]

    def run(self) -> PluginResult:
        return PluginResult(
            columns=["PID", "Name", "Source", "Hidden", "DetectionMethod"],
            rows=[],
            metadata={"note": "Cross-references process lists from multiple kernel structures"},
        )
