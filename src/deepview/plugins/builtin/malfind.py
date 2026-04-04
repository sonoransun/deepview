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
        from pathlib import Path
        from deepview.memory.manager import MemoryManager
        from deepview.detection.injection import InjectionDetector

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        try:
            MemoryManager(self.context)  # validate context is usable
            InjectionDetector()  # validate detector can be created
            # Without an analysis engine providing VAD data, we can't
            # inspect memory regions yet.
            return PluginResult(
                columns=["PID", "Process", "Address", "VadTag", "Protection", "Flags", "Hexdump"],
                rows=[],
                metadata={
                    "note": (
                        "Injection detection requires an analysis engine "
                        "(volatility3 or memprocfs) to enumerate VAD entries"
                    ),
                },
            )
        except Exception as e:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": str(e)}],
            )
