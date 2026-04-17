"""ext2/3/4 adapter via ``pyfsext`` (libfsext)."""
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


ADAPTER_NAME = "ext"


def _import() -> Any:
    try:
        import pyfsext  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise StorageError("pyfsext not installed") from exc
    return pyfsext


class _FileLayer(DataLayer):
    def __init__(self, f: Any, name: str) -> None:
        self._f = f
        self._name = name
        self._size = int(getattr(f, "size", 0) or 0)

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


class EXTFilesystem(Filesystem):
    fs_name = "ext"

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)
        mod = _import()
        self._io = LayerFileIO(layer, offset=offset)
        v = mod.volume()
        try:
            v.open_file_object(self._io)
        except Exception as exc:
            raise StorageError(f"pyfsext open failed: {exc}") from exc
        self._volume = v

    @classmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        try:
            mod = _import()
        except StorageError:
            return False
        io = LayerFileIO(layer, offset=offset)
        v = mod.volume()
        try:
            v.open_file_object(io)
            return True
        except Exception:
            return False

    def _to_entry(self, path: str, f: Any) -> FSEntry:
        return FSEntry(
            path=path,
            inode=int(getattr(f, "inode_number", 0) or 0),
            size=int(getattr(f, "size", 0) or 0),
            mode=int(getattr(f, "file_mode", 0) or 0),
            uid=int(getattr(f, "owner_identifier", 0) or 0),
            gid=int(getattr(f, "group_identifier", 0) or 0),
            mtime=float(getattr(f, "modification_time_as_integer", 0) or 0),
            atime=float(getattr(f, "access_time_as_integer", 0) or 0),
            ctime=float(getattr(f, "inode_change_time_as_integer", 0) or 0),
            btime=(float(getattr(f, "creation_time_as_integer", 0) or 0)) or None,
            is_dir=bool(getattr(f, "number_of_sub_file_entries", 0)),
            is_symlink=bool(getattr(f, "symbolic_link_target", "") or ""),
            extra={"fs": "ext"},
        )

    def _walk(self, entry: Any, path: str, *, recursive: bool) -> Iterator[FSEntry]:
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
                    yield from self._walk(child, full, recursive=True)
                except Exception:
                    continue

    def list(self, path: str = "/", *, recursive: bool = False, include_deleted: bool = False) -> Iterator[FSEntry]:
        try:
            e = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsext path {path!r}: {exc}") from exc
        yield from self._walk(e, path, recursive=recursive)

    def stat(self, path: str) -> FSEntry:
        try:
            f = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsext stat {path!r}: {exc}") from exc
        return self._to_entry(path, f)

    def open(self, path: str) -> DataLayer:
        try:
            f = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsext open {path!r}: {exc}") from exc
        return _FileLayer(f, name=path)

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        layer = self.open(path)
        if length < 0:
            length = layer.maximum_address + 1 - offset
        return layer.read(offset, max(0, length))


ADAPTER_CLASS = EXTFilesystem


def register(manager: Any) -> None:
    manager.register_filesystem(ADAPTER_NAME, ADAPTER_CLASS)
