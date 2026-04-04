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
        from pathlib import Path
        from deepview.memory.manager import MemoryManager
        from deepview.detection.anti_forensics import AntiForensicsDetector

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        try:
            MemoryManager(self.context)  # validate context is usable
            AntiForensicsDetector()  # validate detector can be created
            # Without multiple process sources, we can't do DKOM yet
            return PluginResult(
                columns=["PID", "Name", "Source", "Hidden", "DetectionMethod"],
                rows=[],
                metadata={
                    "note": (
                        "DKOM detection requires an analysis engine "
                        "(volatility3 or memprocfs) for multiple process "
                        "source comparison"
                    ),
                },
            )
        except Exception as e:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": str(e)}],
            )
