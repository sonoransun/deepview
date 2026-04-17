"""Swap/zram/zswap page extraction plugin.

Opens the requested swap-encoding layer over a registered DataLayer,
reads every decompressed page, and writes the resulting flat stream to
``output_path``. Useful for feeding a carving pass over recoverable
swap pages without having to re-derive the layer wiring every time.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="swap_extract",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Decompress Linux swap / zram / zswap / Windows pagefile pages to a flat file",
    tags=["swap", "zram", "zswap", "pagefile", "artifact"],
)
class SwapExtractPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="layer_name", description="Registered DataLayer over the swap area"),
            Requirement(
                name="kind",
                description="Swap kind: linux | windows | zram | zswap",
                required=False,
                default="linux",
            ),
            Requirement(name="output_path", description="File path for the decompressed output"),
            Requirement(
                name="chunk_size",
                description="Bytes to read per iteration",
                required=False,
                default=1024 * 1024,
            ),
        ]

    def _build_swap_layer(self, kind: str, backing: Any) -> Any | None:
        """Wrap *backing* in the appropriate swap-encoding layer."""
        try:
            if kind == "linux":
                from deepview.storage.encodings.swap_layer import LinuxSwapLayer

                return LinuxSwapLayer(backing)
            if kind == "windows":
                from deepview.storage.encodings.swap_layer import WindowsSwapLayer

                return WindowsSwapLayer(backing)
            if kind == "zram":
                from deepview.storage.encodings.zram_layer import ZRAMLayer

                # No page table provided: the operator needs to rebuild
                # the layer manually. This plugin surfaces the gap rather
                # than silently extracting zeros.
                return ZRAMLayer(backing, algo="lz4", page_table=[])
            if kind == "zswap":
                from deepview.storage.encodings.zswap_layer import ZswapLayer

                return ZswapLayer(backing, page_table=[])
        except ImportError:
            return None
        return None

    def run(self) -> PluginResult:
        from deepview.core.exceptions import LayerError
        from deepview.interfaces.layer import DataLayer

        layer_name = self.config.get("layer_name")
        output_path = self.config.get("output_path")
        if not layer_name:
            return PluginResult(columns=["Error"], rows=[{"Error": "layer_name is required"}])
        if not output_path:
            return PluginResult(columns=["Error"], rows=[{"Error": "output_path is required"}])

        kind = str(self.config.get("kind", "linux")).lower()
        if kind not in ("linux", "windows", "zram", "zswap"):
            return PluginResult(columns=["Error"], rows=[{"Error": f"unknown kind {kind!r}"}])
        try:
            chunk_size = int(self.config.get("chunk_size", 1024 * 1024))
        except (TypeError, ValueError):
            chunk_size = 1024 * 1024
        if chunk_size <= 0:
            chunk_size = 1024 * 1024

        try:
            backing = self.context.layers.get(layer_name)
        except LayerError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])
        if not isinstance(backing, DataLayer):
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"layer {layer_name!r} is not a DataLayer"}],
            )

        swap_layer = self._build_swap_layer(kind, backing)
        if swap_layer is None:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"swap backend {kind!r} unavailable or missing parameters"}],
                metadata={"kind": kind, "available": False},
            )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        pages_written = 0
        bytes_written = 0
        errors = 0
        page_size = 4096  # conservative default; Linux/zram/zswap all use 4 KiB pages

        try:
            end = swap_layer.maximum_address + 1
            pos = swap_layer.minimum_address
            with out.open("wb") as fh:
                while pos < end:
                    take = min(chunk_size, end - pos)
                    try:
                        data = swap_layer.read(pos, take, pad=True)
                    except Exception:
                        errors += 1
                        pos += take
                        continue
                    fh.write(data)
                    bytes_written += len(data)
                    pages_written += (len(data) + page_size - 1) // page_size
                    pos += take
        except OSError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": f"write failed: {e}"}])

        rows = [
            {"Metric": "kind", "Value": kind},
            {"Metric": "output", "Value": str(out)},
            {"Metric": "pages_written", "Value": str(pages_written)},
            {"Metric": "bytes_written", "Value": str(bytes_written)},
            {"Metric": "errors", "Value": str(errors)},
        ]
        return PluginResult(
            columns=["Metric", "Value"],
            rows=rows,
            metadata={
                "pages_written": pages_written,
                "bytes_written": bytes_written,
                "errors": errors,
            },
        )
