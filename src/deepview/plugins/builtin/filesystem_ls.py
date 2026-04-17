"""Filesystem directory listing plugin.

Opens a filesystem over a registered layer and returns a
:class:`PluginResult` with POSIX-ish metadata for every entry under *path*.
"""
from __future__ import annotations

import stat as stat_mod
from datetime import datetime, timezone

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


def _fmt_mode(mode: int) -> str:
    try:
        return stat_mod.filemode(mode)
    except Exception:
        return f"{mode:06o}"


def _fmt_time(ts: float | None) -> str:
    if ts is None or ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError):
        return ""


@register_plugin(
    name="filesystem_ls",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="List directory entries from a registered DataLayer + filesystem",
    tags=["filesystem", "ls", "artifact"],
)
class FilesystemListPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="layer_name", description="Registered DataLayer name"),
            Requirement(
                name="fs_type",
                description="Filesystem adapter (default: auto-probe)",
                required=False,
                default="auto",
            ),
            Requirement(
                name="path",
                description="Directory to list (default /)",
                required=False,
                default="/",
            ),
            Requirement(
                name="recursive",
                description="Recurse into subdirectories (default False)",
                required=False,
                default=False,
            ),
            Requirement(
                name="include_deleted",
                description="Include deleted entries where the FS exposes them",
                required=False,
                default=False,
            ),
            Requirement(
                name="offset",
                description="Byte offset into the layer at which the FS begins",
                required=False,
                default=0,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.core.exceptions import LayerError
        from deepview.interfaces.layer import DataLayer
        from deepview.storage.filesystems.registry import register_all
        from deepview.storage.manager import StorageError

        layer_name = self.config.get("layer_name")
        if not layer_name:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "layer_name is required"}],
            )
        fs_type_raw = self.config.get("fs_type", "auto")
        fs_type = None if not fs_type_raw or str(fs_type_raw).lower() == "auto" else str(fs_type_raw)
        path = str(self.config.get("path", "/"))
        recursive = bool(self.config.get("recursive", False))
        include_deleted = bool(self.config.get("include_deleted", False))
        try:
            offset = int(self.config.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0

        mgr = self.context.storage
        if not mgr.filesystems():
            try:
                register_all(mgr)
            except Exception:  # pragma: no cover - defensive
                pass

        try:
            obj = self.context.layers.get(layer_name)
        except LayerError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])
        if not isinstance(obj, DataLayer):
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"layer {layer_name!r} is not a DataLayer"}],
            )

        try:
            fs = mgr.open_filesystem(obj, fs_type=fs_type, offset=offset)
        except StorageError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        rows: list[dict] = []
        total = 0
        try:
            for entry in fs.list(path, recursive=recursive, include_deleted=include_deleted):
                total += 1
                rows.append(
                    {
                        "Path": entry.path,
                        "Size": str(entry.size),
                        "Mode": _fmt_mode(entry.mode),
                        "MTime": _fmt_time(entry.mtime),
                        "Deleted": "yes" if entry.is_deleted else "",
                    }
                )
        except StorageError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        return PluginResult(
            columns=["Path", "Size", "Mode", "MTime", "Deleted"],
            rows=rows,
            metadata={
                "total_found": total,
                "fs_type": fs.fs_name or (fs_type or "auto"),
                "path": path,
            },
        )
