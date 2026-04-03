"""Page table walk plugin — enumerates virtual-to-physical mappings."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="pagetable_walk",
    category=PluginCategory.MEMORY_ANALYSIS,
    description="Walk page tables to enumerate virtual-to-physical mappings",
    tags=["memory", "translation", "page_tables"],
)
class PageTableWalkPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(
                name="cr3",
                description="CR3 register value (hex). If omitted, scans for candidates.",
                required=False,
            ),
            Requirement(
                name="limit",
                description="Max mappings to return (default 1000)",
                required=False,
                default=1000,
            ),
        ]

    def run(self) -> PluginResult:
        from pathlib import Path

        from deepview.memory.manager import MemoryManager
        from deepview.memory.translation.page_tables import PageTableWalker

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        mm = MemoryManager(self.context)
        layer = mm.open_layer(Path(image_path))
        walker = PageTableWalker(layer)

        cr3_str = self.config.get("cr3")
        limit = int(self.config.get("limit", 1000))

        if cr3_str:
            cr3 = int(cr3_str, 16) if isinstance(cr3_str, str) else int(cr3_str)
            cr3_values = [cr3]
        else:
            cr3_values = list(walker.scan_for_cr3_candidates(min_mappings=10))[:5]
            if not cr3_values:
                return PluginResult(
                    columns=["Error"],
                    rows=[{"Error": "No valid CR3 candidates found"}],
                )

        rows = []
        for cr3 in cr3_values:
            count = 0
            for mapping in walker.walk_all_mappings(cr3):
                if count >= limit:
                    break
                rows.append({
                    "CR3": f"0x{cr3:x}",
                    "Virtual": f"0x{mapping.virtual_start:x}",
                    "Physical": f"0x{mapping.physical_start:x}",
                    "Size": _format_size(mapping.size),
                    "RW": "W" if mapping.writable else "R",
                    "User": "U" if mapping.user else "K",
                    "NX": "NX" if mapping.no_execute else "--",
                    "Level": str(mapping.level),
                })
                count += 1

        return PluginResult(
            columns=["CR3", "Virtual", "Physical", "Size", "RW", "User", "NX", "Level"],
            rows=rows,
            metadata={"cr3_candidates": [f"0x{c:x}" for c in cr3_values]},
        )


def _format_size(size: int) -> str:
    if size >= 1024 * 1024 * 1024:
        return f"{size // (1024 * 1024 * 1024)}G"
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)}M"
    if size >= 1024:
        return f"{size // 1024}K"
    return str(size)
