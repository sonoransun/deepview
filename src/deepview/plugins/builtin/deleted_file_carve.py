"""Deleted-file / slack-space carving plugin.

Iterates :meth:`Filesystem.unallocated` (each adapter reports whatever it
can: TSK exposes deleted inodes, ``fat_native`` surfaces ``0xE5`` entries
when asked, APFS/NTFS natives expose their own deletion ghosts) and then
runs the string carver over the slack/unallocated byte regions to surface
anything recognisable.
"""
from __future__ import annotations

from typing import Any

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="deleted_file_carve",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Carve deleted filesystem entries and slack-space strings",
    tags=["filesystem", "carve", "deleted", "artifact"],
)
class DeletedFileCarvePlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="layer_name", description="Registered DataLayer"),
            Requirement(
                name="fs_type",
                description="Filesystem adapter (default: auto-probe)",
                required=False,
                default="auto",
            ),
            Requirement(
                name="offset",
                description="Byte offset into the layer at which the FS begins",
                required=False,
                default=0,
            ),
            Requirement(
                name="max_strings",
                description="Stop after this many carved strings",
                required=False,
                default=1000,
            ),
            Requirement(
                name="min_length",
                description="Minimum carved-string length",
                required=False,
                default=6,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.core.exceptions import LayerError
        from deepview.interfaces.layer import DataLayer
        from deepview.scanning.string_carver import StringCarver
        from deepview.storage.filesystems.registry import register_all
        from deepview.storage.manager import StorageError

        layer_name = self.config.get("layer_name")
        if not layer_name:
            return PluginResult(columns=["Error"], rows=[{"Error": "layer_name is required"}])
        fs_type_raw = self.config.get("fs_type", "auto")
        fs_type = None if not fs_type_raw or str(fs_type_raw).lower() == "auto" else str(fs_type_raw)
        try:
            offset = int(self.config.get("offset", 0))
            max_strings = int(self.config.get("max_strings", 1000))
            min_length = int(self.config.get("min_length", 6))
        except (TypeError, ValueError) as e:
            return PluginResult(columns=["Error"], rows=[{"Error": f"bad int: {e}"}])

        mgr = self.context.storage
        if not mgr.filesystems():
            try:
                register_all(mgr)
            except Exception:  # pragma: no cover - defensive
                pass

        try:
            layer_obj = self.context.layers.get(layer_name)
        except LayerError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])
        if not isinstance(layer_obj, DataLayer):
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"layer {layer_name!r} is not a DataLayer"}],
            )

        try:
            fs = mgr.open_filesystem(layer_obj, fs_type=fs_type, offset=offset)
        except StorageError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        rows: list[dict] = []
        deleted_count = 0
        string_count = 0

        # 1) Enumerate filesystem-reported unallocated / deleted entries.
        try:
            for entry in fs.unallocated():
                deleted_count += 1
                rows.append(
                    {
                        "Source": "deleted_entry",
                        "Offset": str(entry.inode),
                        "Size": str(entry.size),
                        "Snippet": entry.path,
                    }
                )
        except StorageError as e:
            rows.append(
                {
                    "Source": "error",
                    "Offset": "-",
                    "Size": "-",
                    "Snippet": f"unallocated(): {e}",
                }
            )

        # 2) Run the string carver over the raw layer. This is the closest
        # cross-adapter proxy for "slack / unallocated space" without having
        # to reach into every FS's internal free-cluster map.
        try:
            carver = StringCarver(min_length=max(min_length, 4))
        except ValueError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        for result in carver.scan_layer(layer_obj):
            if string_count >= max_strings:
                break
            metadata = result.metadata or {}
            value: Any = metadata.get("string_value", "")
            rows.append(
                {
                    "Source": "slack_string",
                    "Offset": f"0x{result.offset:x}",
                    "Size": str(result.length),
                    "Snippet": str(value)[:200],
                }
            )
            string_count += 1

        return PluginResult(
            columns=["Source", "Offset", "Size", "Snippet"],
            rows=rows,
            metadata={
                "deleted_entries": deleted_count,
                "slack_strings": string_count,
                "fs_type": fs.fs_name or (fs_type or "auto"),
            },
        )
