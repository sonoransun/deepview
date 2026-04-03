"""Command history extraction plugin."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="command_history",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Extract shell command history from memory (cmd, PowerShell, bash)",
    tags=["commands", "history", "shell", "artifacts"],
)
class CommandHistoryPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(
                name="limit",
                description="Max commands to return (default 500)",
                required=False,
                default=500,
            ),
        ]

    def run(self) -> PluginResult:
        from pathlib import Path

        from deepview.memory.artifacts.command_history import CommandHistoryExtractor
        from deepview.memory.manager import MemoryManager

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        limit = int(self.config.get("limit", 500))

        mm = MemoryManager(self.context)
        layer = mm.open_layer(Path(image_path))
        extractor = CommandHistoryExtractor(layer)
        entries = extractor.extract_all()

        rows = []
        for entry in entries[:limit]:
            rows.append({
                "Shell": entry.shell_type,
                "Command": entry.command[:200],
                "Offset": f"0x{entry.offset:x}",
                "PID": str(entry.pid) if entry.pid else "",
            })

        return PluginResult(
            columns=["Shell", "Command", "Offset", "PID"],
            rows=rows,
            metadata={"total_found": len(entries)},
        )
