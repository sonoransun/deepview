"""Process listing plugin."""
from __future__ import annotations
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

@register_plugin(
    name="pslist",
    category=PluginCategory.MEMORY_ANALYSIS,
    description="List running processes from a memory image",
    tags=["processes", "memory"],
)
class ProcessListPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(name="engine", description="Analysis engine", required=False, default="auto"),
            Requirement(name="pid", description="Filter by PID", required=False),
        ]

    def run(self) -> PluginResult:
        from deepview.memory.manager import MemoryManager
        from pathlib import Path

        config = self.config or {}
        image_path = config.get("image_path")
        engine_name = config.get("engine", "auto")
        pid_filter = config.get("pid")

        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "No image path provided"}],
            )

        manager = MemoryManager(self.context)

        try:
            engine = manager.get_engine(engine_name)

            if engine.engine_name() == "volatility":
                layer = engine.open_image(Path(image_path))
                result = engine.run_plugin("windows.pslist.PsList", layer)
                # Convert Volatility output to our format
                rows = []
                if hasattr(result, '__iter__'):
                    for row in result:
                        rows.append(dict(row))
                return PluginResult(
                    columns=["PID", "PPID", "Name", "Threads", "Handles", "CreateTime"],
                    rows=rows,
                )
            elif engine.engine_name() == "memprocfs":
                processes = engine.run_plugin("processes", None, image_path=image_path)
                rows = []
                for proc in processes:
                    if pid_filter and proc.get("pid") != pid_filter:
                        continue
                    rows.append({
                        "PID": str(proc.get("pid", "")),
                        "PPID": str(proc.get("ppid", "")),
                        "Name": proc.get("name", ""),
                    })
                return PluginResult(
                    columns=["PID", "PPID", "Name"],
                    rows=rows,
                )
        except Exception as e:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": str(e)}],
            )

        return PluginResult()
