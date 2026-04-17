from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from deepview.interfaces.layer import DataLayer


@dataclass(frozen=True)
class FSEntry:
    """Single filesystem entry returned by a :class:`Filesystem` adapter."""

    path: str
    inode: int
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    atime: float
    ctime: float
    btime: float | None = None
    is_dir: bool = False
    is_symlink: bool = False
    is_deleted: bool = False
    target: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


class Filesystem(ABC):
    """Adapter exposing a POSIX-ish view over a backing :class:`DataLayer`.

    Concrete adapters are *consumers* of a layer, not subclasses of one — the
    layer is the byte source, the filesystem object is the structural reader.
    """

    fs_name: str = ""
    block_size: int = 0

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        self.layer = layer
        self.offset = offset

    @classmethod
    @abstractmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        """Return ``True`` when this adapter recognises the structure at *offset*."""

    @abstractmethod
    def list(
        self,
        path: str = "/",
        *,
        recursive: bool = False,
        include_deleted: bool = False,
    ) -> Iterator[FSEntry]:
        """Iterate entries beneath *path*."""

    @abstractmethod
    def stat(self, path: str) -> FSEntry:
        """Return the :class:`FSEntry` for *path*."""

    @abstractmethod
    def open(self, path: str) -> DataLayer:
        """Return a :class:`DataLayer` over the file's bytes."""

    @abstractmethod
    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        """Read *length* bytes from *path* starting at *offset* (-1 = all)."""

    def find(self, pattern: str, *, regex: bool = False) -> Iterator[FSEntry]:
        """Default impl walks the tree and matches the basename via fnmatch/regex."""
        import fnmatch
        import re

        matcher = re.compile(pattern).search if regex else (
            lambda name: fnmatch.fnmatchcase(name, pattern)
        )
        for entry in self.list("/", recursive=True):
            base = entry.path.rsplit("/", 1)[-1]
            if matcher(base):
                yield entry

    def unallocated(self) -> Iterator[FSEntry]:
        """Iterate carved/slack/deleted entries. Default: no unallocated reporting."""
        return iter(())

    def close(self) -> None:
        """Release any backend resources. Default no-op."""
        return None
