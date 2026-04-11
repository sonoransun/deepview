"""On-demand file inspector.

Given a path, produce a PluginResult-shaped bundle with hash, size,
magic bytes, ELF/script detection, and the owning mount.
"""
from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from deepview.interfaces.plugin import PluginResult
from deepview.tracing.linux import procfs


class FileInspector:
    """Lightweight metadata-first file inspection."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def to_plugin_result(self) -> PluginResult:
        p = self._path
        rows: list[dict] = []
        if not p.exists():
            return PluginResult(columns=["Error"], rows=[{"Error": f"{p} does not exist"}])

        st = p.stat()
        rows.append({"Key": "path", "Value": str(p)})
        rows.append({"Key": "size", "Value": str(st.st_size)})
        rows.append({"Key": "mode", "Value": stat.filemode(st.st_mode)})
        rows.append({"Key": "uid", "Value": str(st.st_uid)})
        rows.append({"Key": "gid", "Value": str(st.st_gid)})
        rows.append({"Key": "mtime", "Value": str(int(st.st_mtime))})

        try:
            with p.open("rb") as f:
                header = f.read(4096)
        except OSError as e:
            rows.append({"Key": "read_error", "Value": str(e)})
            return PluginResult(columns=["Key", "Value"], rows=rows)

        rows.append({"Key": "sha256", "Value": hashlib.sha256(header).hexdigest()})
        rows.append({"Key": "magic", "Value": header[:16].hex()})
        rows.append({"Key": "kind", "Value": _detect_kind(header)})

        mount = self._owning_mount()
        if mount is not None:
            rows.append({"Key": "mount.target", "Value": mount.target})
            rows.append({"Key": "mount.source", "Value": mount.source})
            rows.append({"Key": "mount.fstype", "Value": mount.fstype})

        return PluginResult(columns=["Key", "Value"], rows=rows)

    def _owning_mount(self):
        resolved = self._path.resolve()
        best = None
        best_len = -1
        for m in procfs.iter_mounts():
            if resolved.as_posix().startswith(m.target) and len(m.target) > best_len:
                best = m
                best_len = len(m.target)
        return best


def _detect_kind(header: bytes) -> str:
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header.startswith(b"MZ"):
        return "pe"
    if header.startswith(b"#!"):
        return "script"
    if header.startswith(b"\x89PNG"):
        return "png"
    if header.startswith(b"PK"):
        return "zip"
    if header.startswith(b"\xca\xfe\xba\xbe"):
        return "macho"
    return "data"
