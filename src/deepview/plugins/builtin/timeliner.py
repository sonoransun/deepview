"""Timeline analysis plugin."""
from __future__ import annotations
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

@register_plugin(
    name="timeliner",
    category=PluginCategory.TIMELINE,
    description="Extract temporal artifacts for timeline analysis",
    tags=["timeline", "timestamps", "memory"],
)
class TimelinerPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
        ]

    def run(self) -> PluginResult:
        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        try:
            rows: list[dict] = []
            # Gather any artifacts already collected in the context
            for category in self.context.artifacts.categories():
                for artifact in self.context.artifacts.get(category):
                    ts = artifact.get("timestamp", "")
                    desc = artifact.get("description", artifact.get("name", ""))
                    rows.append(
                        {
                            "Timestamp": str(ts),
                            "Type": category,
                            "Description": str(desc),
                            "Source": artifact.get("source", "context"),
                        }
                    )

            # Sort by timestamp if available
            rows.sort(key=lambda r: r["Timestamp"])

            return PluginResult(
                columns=["Timestamp", "Type", "Description", "Source"],
                rows=rows,
                metadata={"total_artifacts": len(rows)},
            )
        except Exception as e:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": str(e)}],
            )
