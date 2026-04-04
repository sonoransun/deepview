"""String carving plugin — extract printable strings across encodings."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="strings",
    category=PluginCategory.MEMORY_ANALYSIS,
    description="Carve printable strings from memory with multi-encoding support",
    tags=["strings", "carving", "encoding"],
)
class StringsPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(
                name="min_length",
                description="Minimum string length (default 4)",
                required=False,
                default=4,
            ),
            Requirement(
                name="encodings",
                description="Comma-separated encodings (default: ascii,utf-16-le)",
                required=False,
                default="ascii,utf-16-le",
            ),
            Requirement(
                name="entropy_threshold",
                description="Skip regions above this entropy (default 7.5)",
                required=False,
                default=7.5,
            ),
            Requirement(
                name="limit",
                description="Max strings to return (default 5000)",
                required=False,
                default=5000,
            ),
        ]

    def run(self) -> PluginResult:
        from pathlib import Path

        from deepview.memory.manager import MemoryManager
        from deepview.scanning.string_carver import StringCarver

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        try:
            min_length = int(self.config.get("min_length", 4))
            entropy_threshold = float(self.config.get("entropy_threshold", 7.5))
            limit = int(self.config.get("limit", 5000))
        except (TypeError, ValueError) as e:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"Invalid config value: {e}"}],
            )
        encodings_str = self.config.get("encodings", "ascii,utf-16-le")
        encodings = [e.strip() for e in encodings_str.split(",")]

        mm = MemoryManager(self.context)
        layer = mm.open_layer(Path(image_path))

        carver = StringCarver(
            min_length=min_length,
            encodings=encodings,
            entropy_threshold=entropy_threshold,
        )

        rows = []
        for result in carver.scan_layer(layer):
            if len(rows) >= limit:
                break
            rows.append({
                "Offset": f"0x{result.offset:x}",
                "Encoding": result.metadata.get("encoding", ""),
                "Length": str(result.length),
                "String": result.metadata.get("string_value", "")[:120],
                "Entropy": f"{result.metadata.get('context_entropy', 0):.2f}",
            })

        return PluginResult(
            columns=["Offset", "Encoding", "Length", "String", "Entropy"],
            rows=rows,
            metadata={"total_found": len(rows), "encodings": encodings},
        )
