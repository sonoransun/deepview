"""Native NTFS adapter via ``pyfsntfs`` (libfsntfs).

Exposes Alternate Data Streams and MFT record numbers in each entry's
``extra`` mapping — detail that TSK discards. When both adapters are
registered, the storage manager prefers the adapter that probes first,
so callers should ``open_filesystem(layer, fs_type="ntfs_native")`` to
opt in explicitly.
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


ADAPTER_NAME = "ntfs_native"


def _import() -> Any:
    try:
        import pyfsntfs  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise StorageError("pyfsntfs not installed") from exc
    return pyfsntfs


class _NTFSFileLayer(DataLayer):
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


class NTFSFilesystem(Filesystem):
    fs_name = "ntfs_native"

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)
        mod = _import()
        self._mod = mod
        self._io = LayerFileIO(layer, offset=offset)
        vol = mod.volume()
        try:
            vol.open_file_object(self._io)
        except Exception as exc:
            raise StorageError(f"pyfsntfs open failed: {exc}") from exc
        self._volume = vol
        self.block_size = int(getattr(vol, "cluster_block_size", 0) or 0)

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

    def _ads(self, f: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            n = int(getattr(f, "number_of_alternate_data_streams", 0) or 0)
            for i in range(n):
                s = f.get_alternate_data_stream(i)
                out.append({"name": s.name or "", "size": int(getattr(s, "size", 0) or 0)})
        except Exception:
            pass
        return out

    def _to_entry(self, path: str, f: Any) -> FSEntry:
        extra: dict[str, Any] = {
            "fs": "ntfs_native",
            "ads": self._ads(f),
            "mft_record": int(getattr(f, "file_reference", 0) or 0),
        }
        return FSEntry(
            path=path,
            inode=int(getattr(f, "file_reference", 0) or 0),
            size=int(getattr(f, "size", 0) or 0),
            mode=0,
            uid=0,
            gid=0,
            mtime=float(getattr(f, "modification_time_as_integer", 0) or 0) / 1e7,
            atime=float(getattr(f, "access_time_as_integer", 0) or 0) / 1e7,
            ctime=float(getattr(f, "entry_modification_time_as_integer", 0) or 0) / 1e7,
            btime=(float(getattr(f, "creation_time_as_integer", 0) or 0) / 1e7) or None,
            is_dir=bool(getattr(f, "number_of_sub_file_entries", 0)),
            is_symlink=False,
            extra=extra,
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
            entry = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsntfs path {path!r}: {exc}") from exc
        yield from self._walk(entry, path, recursive=recursive)

    def stat(self, path: str) -> FSEntry:
        try:
            f = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsntfs stat {path!r}: {exc}") from exc
        return self._to_entry(path, f)

    def open(self, path: str) -> DataLayer:
        try:
            f = self._volume.get_file_entry_by_path(path)
        except Exception as exc:
            raise StorageError(f"pyfsntfs open {path!r}: {exc}") from exc
        return _NTFSFileLayer(f, name=path)

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        layer = self.open(path)
        if length < 0:
            length = layer.maximum_address + 1 - offset
        return layer.read(offset, max(0, length))


ADAPTER_CLASS = NTFSFilesystem


def register(manager: Any) -> None:
    manager.register_filesystem(ADAPTER_NAME, ADAPTER_CLASS)
