"""The Sleuth Kit filesystem adapter.

Wraps ``pytsk3`` to expose ext2/3/4, FAT12/16/32, exFAT, NTFS, HFS+, ISO9660,
and UFS behind the common :class:`Filesystem` interface. All calls into
``pytsk3`` are lazy-imported from within method bodies so the rest of Deep
View imports cleanly on systems without the optional ``storage`` extra.
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


ADAPTER_NAME = "tsk"


def _import_pytsk3() -> Any:
    try:
        import pytsk3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - requires missing dep
        raise StorageError("pytsk3 not installed") from exc
    return pytsk3


def _build_img_info(layer: DataLayer, offset: int) -> Any:
    """Construct a pytsk3 ``Img_Info`` subclass backed by a :class:`DataLayer`."""
    pytsk3 = _import_pytsk3()

    class _LayerImg(pytsk3.Img_Info):  # type: ignore[misc]
        def __init__(self) -> None:
            self._io = LayerFileIO(layer, offset=offset)
            super().__init__(url="")

        def close(self) -> None:
            self._io.close()

        def read(self, off: int, size: int) -> bytes:
            self._io.seek(off)
            return self._io.read(size)

        def get_size(self) -> int:
            return self._io.get_size()

    return _LayerImg()


class TSKFileLayer(DataLayer):
    """A :class:`DataLayer` over a single file inside a TSK-mounted filesystem."""

    def __init__(self, tsk_file: Any, name: str = "") -> None:
        self._file = tsk_file
        self._name = name
        meta = getattr(tsk_file, "info", None)
        meta_meta = getattr(meta, "meta", None) if meta is not None else None
        self._size = int(getattr(meta_meta, "size", 0) or 0)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        want = min(length, self._size - offset)
        if want <= 0:
            return b"\x00" * length if pad else b""
        try:
            data = bytes(self._file.read_random(offset, want))
        except Exception as exc:  # pragma: no cover - backend-dependent
            raise StorageError(f"TSK read_random failed: {exc}") from exc
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("TSKFileLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= self._size

    def scan(
        self,
        scanner: Any,
        progress_callback: "Callable[[float], None] | None" = None,
    ) -> Iterator[ScanResult]:
        chunk = 1 << 20
        off = 0
        while off < self._size:
            buf = self.read(off, min(chunk, self._size - off))
            if not buf:
                break
            for result in scanner.scan(buf, offset=off):
                yield result
            if progress_callback is not None:
                progress_callback(min(1.0, (off + len(buf)) / max(1, self._size)))
            off += len(buf)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, self._size - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name or "tsk_file",
            minimum_address=0,
            maximum_address=max(0, self._size - 1),
        )


class TSKFilesystem(Filesystem):
    """pytsk3-backed filesystem adapter."""

    fs_name = "tsk"

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)
        pytsk3 = _import_pytsk3()
        self._pytsk3 = pytsk3
        self._img = _build_img_info(layer, offset)
        try:
            self._fs = pytsk3.FS_Info(self._img)
        except Exception as exc:
            raise StorageError(f"TSK failed to open filesystem: {exc}") from exc
        info = getattr(self._fs, "info", None)
        self.block_size = int(getattr(info, "block_size", 0) or 0)

    @classmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        try:
            pytsk3 = _import_pytsk3()
        except StorageError:
            return False
        try:
            img = _build_img_info(layer, offset)
            pytsk3.FS_Info(img)
        except Exception:
            return False
        return True

    # ------------------------------------------------------------------
    # Directory / file operations
    # ------------------------------------------------------------------

    def list(
        self,
        path: str = "/",
        *,
        recursive: bool = False,
        include_deleted: bool = False,
    ) -> Iterator[FSEntry]:
        yield from self._walk(path, recursive=recursive, include_deleted=include_deleted)

    def _walk(
        self, path: str, *, recursive: bool, include_deleted: bool
    ) -> Iterator[FSEntry]:
        try:
            directory = self._fs.open_dir(path=path)
        except Exception as exc:
            raise StorageError(f"TSK open_dir({path!r}) failed: {exc}") from exc
        for entry in directory:
            name_bytes = getattr(entry.info.name, "name", b"") or b""
            name = name_bytes.decode("utf-8", errors="replace")
            if name in ("", ".", ".."):
                continue
            meta = entry.info.meta
            flags = int(getattr(entry.info.name, "flags", 0) or 0)
            is_deleted = bool(flags & int(getattr(self._pytsk3, "TSK_FS_NAME_FLAG_UNALLOC", 0)))
            if is_deleted and not include_deleted:
                continue
            full = f"{path.rstrip('/')}/{name}"
            fsentry = self._entry_from_meta(full, name, meta, is_deleted=is_deleted)
            yield fsentry
            if recursive and fsentry.is_dir:
                try:
                    yield from self._walk(
                        full, recursive=True, include_deleted=include_deleted
                    )
                except StorageError:
                    continue

    def _entry_from_meta(
        self, path: str, name: str, meta: Any, *, is_deleted: bool
    ) -> FSEntry:
        if meta is None:
            return FSEntry(
                path=path, inode=0, size=0, mode=0,
                uid=0, gid=0, mtime=0.0, atime=0.0, ctime=0.0,
                is_deleted=is_deleted,
            )
        mode = int(getattr(meta, "mode", 0) or 0)
        meta_type = int(getattr(meta, "type", 0) or 0)
        is_dir = meta_type == int(getattr(self._pytsk3, "TSK_FS_META_TYPE_DIR", -1))
        is_sym = meta_type == int(getattr(self._pytsk3, "TSK_FS_META_TYPE_LNK", -1))
        return FSEntry(
            path=path,
            inode=int(getattr(meta, "addr", 0) or 0),
            size=int(getattr(meta, "size", 0) or 0),
            mode=mode,
            uid=int(getattr(meta, "uid", 0) or 0),
            gid=int(getattr(meta, "gid", 0) or 0),
            mtime=float(getattr(meta, "mtime", 0) or 0),
            atime=float(getattr(meta, "atime", 0) or 0),
            ctime=float(getattr(meta, "ctime", 0) or 0),
            btime=float(getattr(meta, "crtime", 0) or 0) or None,
            is_dir=is_dir,
            is_symlink=is_sym,
            is_deleted=is_deleted,
            extra={"fs": "tsk", "name": name},
        )

    def stat(self, path: str) -> FSEntry:
        try:
            f = self._fs.open(path)
        except Exception as exc:
            raise StorageError(f"TSK open({path!r}) failed: {exc}") from exc
        name = path.rsplit("/", 1)[-1]
        return self._entry_from_meta(path, name, f.info.meta, is_deleted=False)

    def open(self, path: str) -> DataLayer:
        try:
            f = self._fs.open(path)
        except Exception as exc:
            raise StorageError(f"TSK open({path!r}) failed: {exc}") from exc
        return TSKFileLayer(f, name=path)

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        layer = self.open(path)
        if length < 0:
            length = layer.maximum_address + 1 - offset
        if length <= 0:
            return b""
        return layer.read(offset, length)

    def unallocated(self) -> Iterator[FSEntry]:
        """Walk the volume reporting entries marked ``TSK_FS_BLOCK_FLAG_UNALLOC``."""
        pytsk3 = self._pytsk3
        unalloc_flag = int(getattr(pytsk3, "TSK_FS_BLOCK_FLAG_UNALLOC", 0))
        if unalloc_flag == 0:
            return
        yield from self._walk("/", recursive=True, include_deleted=True)

    def close(self) -> None:
        try:
            self._img.close()
        except Exception:
            pass


ADAPTER_CLASS = TSKFilesystem


def register(manager: Any) -> None:
    """Register this adapter with a :class:`StorageManager`."""
    manager.register_filesystem(ADAPTER_NAME, ADAPTER_CLASS)
