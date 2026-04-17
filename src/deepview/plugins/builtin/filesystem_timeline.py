"""Filesystem bodyfile-style timeline plugin.

Walks the filesystem recursively and yields one row per entry per
timestamp (mtime / atime / ctime / btime). Similar in shape to
``mactime`` output but emitted as a structured :class:`PluginResult`.
"""
from __future__ import annotations

from datetime import datetime, timezone

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


_TIME_KINDS: tuple[tuple[str, str], ...] = (
    ("mtime", "m"),
    ("atime", "a"),
    ("ctime", "c"),
    ("btime", "b"),
)


def _fmt_time(ts: float | None) -> str:
    if ts is None or ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError):
        return ""


@register_plugin(
    name="filesystem_timeline",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Walk a filesystem and emit a bodyfile-style MAC-times timeline",
    tags=["filesystem", "timeline", "mactime", "artifact"],
)
class FilesystemTimelinePlugin(DeepViewPlugin):

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
                name="offset",
                description="Byte offset into the layer at which the FS begins",
                required=False,
                default=0,
            ),
            Requirement(
                name="include_deleted",
                description="Include deleted entries",
                required=False,
                default=True,
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
        try:
            offset = int(self.config.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        include_deleted = bool(self.config.get("include_deleted", True))

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
        total_entries = 0
        try:
            for entry in fs.list("/", recursive=True, include_deleted=include_deleted):
                total_entries += 1
                for field, tag in _TIME_KINDS:
                    ts = getattr(entry, field, None)
                    if ts is None or ts == 0:
                        continue
                    rows.append(
                        {
                            "Time": _fmt_time(ts),
                            "Type": tag,
                            "Path": entry.path + (" (deleted)" if entry.is_deleted else ""),
                            "Size": str(entry.size),
                        }
                    )
        except StorageError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        # Sort chronologically; rows with empty timestamps sink to the end.
        rows.sort(key=lambda r: (not r["Time"], r["Time"]))

        return PluginResult(
            columns=["Time", "Type", "Path", "Size"],
            rows=rows,
            metadata={
                "total_entries": total_entries,
                "total_rows": len(rows),
                "fs_type": fs.fs_name or (fs_type or "auto"),
            },
        )
