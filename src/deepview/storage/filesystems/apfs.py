"""APFS adapter via ``pyfsapfs`` (libfsapfs).

Exposes volumes + snapshots. Per-entry ``extra`` includes the snapshot name
when the entry was read from a snapshot, and the extent list from the
``pyfsapfs`` file-entry when available.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.filesystem import Filesystem, FSEntry
from deepview.interfaces.layer import DataLayer
from deepview.storage.filesystems._layer_io import LayerFileIO
from deepview.storage.manager import StorageError

if TYPE_CHECKING:
    from collections.abc import Callable


ADAPTER_NAME = "apfs"


def _import() -> Any:
    try:
        import pyfsapfs  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise StorageError("pyfsapfs not installed") from exc
    return pyfsapfs


class _PyfsapfsFileLayer(DataLayer):
    def __init__(self, fentry: Any, name: str) -> None:
        self._f = fentry
        self._name = name
        self._size = int(getattr(fentry, "size", 0) or 0)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        self._f.seek_offset(offset, 0)
        n = min(length, self._size - offset)
        data = bytes(self._f.read_buffer(n))
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= self._size

    def scan(self, scanner: Any, progress_callback: "Callable[[float], None] | None" = None) -> Iterator[ScanResult]:
        return iter(())

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, self._size - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name, minimum_address=0, maximum_address=max(0, self._size - 1))


class APFSFilesystem(Filesystem):
    fs_name = "apfs"

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)
        mod = _import()
        self._mod = mod
        self._io = LayerFileIO(layer, offset=offset)
        container = mod.container()
        try:
            container.open_file_object(self._io)
        except Exception as exc:
            raise StorageError(f"pyfsapfs open failed: {exc}") from exc
        self._container = container
        # Primary volume = first volume; snapshots enumerated separately.
        if container.number_of_volumes < 1:
            raise StorageError("pyfsapfs: container has no volumes")
        self._volume = container.get_volume(0)

    @classmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        try:
            mod = _import()
        except StorageError:
            return False
        io = LayerFileIO(layer, offset=offset)
        c = mod.container()
        try:
            c.open_file_object(io)
            return c.number_of_volumes > 0
        except Exception:
            return False

    def _walk_dir(self, entry: Any, path: str, *, recursive: bool) -> Iterator[FSEntry]:
        try:
            n = int(entry.number_of_sub_file_entries)
        except Exception:
            return
        for i in range(n):
            try:
                child = entry.get_sub_file_entry(i)
            except Exception:
                continue
            name = child.name or ""
            if name in ("", ".", ".."):
                continue
            full = f"{path.rstrip('/')}/{name}"
            yield self._to_entry(full, child)
            if recursive:
                try:
                    yield from self._walk_dir(child, full, recursive=True)
                except Exception:
                    continue

    def _to_entry(self, path: str, f: Any) -> FSEntry:
        extents: list[tuple[int, int]] = []
        try:
            nex = int(getattr(f, "number_of_extents", 0) or 0)
            for i in range(nex):
                ex = f.get_extent(i)
                extents.append((int(ex[0]), int(ex[1])))
        except Exception:
            pass
        snapshot = getattr(f, "snapshot_name", "") or ""
        return FSEntry(
            path=path,
            inode=int(getattr(f, "identifier", 0) or 0),
            size=int(getattr(f, "size", 0) or 0),
            mode=int(getattr(f, "file_mode", 0) or 0),
            uid=int(getattr(f, "owner_identifier", 0) or 0),
            gid=int(getattr(f, "group_identifier", 0) or 0),
            mtime=float(getattr(f, "modification_time_as_integer", 0) or 0) / 1e9,
            atime=float(getattr(f, "access_time_as_integer", 0) or 0) / 1e9,
            ctime=float(getattr(f, "inode_change_time_as_integer", 0) or 0) / 1e9,
            btime=(float(getattr(f, "creation_time_as_integer", 0) or 0) / 1e9) or None,
            is_dir=bool(getattr(f, "number_of_sub_file_entries", 0)),
            is_symlink=bool(getattr(f, "symbolic_link_target", "") or ""),
            extra={"fs": "apfs", "snapshot": snapshot, "extents": extents},
        )

    def list(self, path: str = "/", *, recursive: bool = False, include_deleted: bool = False) -> Iterator[FSEntry]:
        try:
            entry = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsapfs path {path!r}: {exc}") from exc
        yield from self._walk_dir(entry, path, recursive=recursive)

    def stat(self, path: str) -> FSEntry:
        try:
            f = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsapfs stat {path!r}: {exc}") from exc
        return self._to_entry(path, f)

    def open(self, path: str) -> DataLayer:
        try:
            f = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsapfs open {path!r}: {exc}") from exc
        return _PyfsapfsFileLayer(f, name=path)

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        layer = self.open(path)
        if length < 0:
            length = layer.maximum_address + 1 - offset
        return layer.read(offset, max(0, length))


ADAPTER_CLASS = APFSFilesystem


def register(manager: Any) -> None:
    manager.register_filesystem(ADAPTER_NAME, ADAPTER_CLASS)
