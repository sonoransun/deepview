"""File-like shim for container adapters.

Encrypted-container C libraries (``libbde`` for BitLocker, ``libfvde`` for
FileVault 2, ``libcryptsetup`` for LUKS) consume their input through a
file-like object with ``read(n)`` / ``seek(pos, whence)`` / ``tell()`` /
``close()`` semantics. The filesystem subsystem already ships an
equivalent :class:`~deepview.storage.filesystems._layer_io.LayerFileIO`
wrapper around a :class:`~deepview.interfaces.layer.DataLayer`; the
container adapters simply re-use that implementation so the two
subsystems cannot drift out of sync.

This module is intentionally a thin alias: if the filesystems slice is
not present (e.g. a partial tree during CI), we fall back to an inline
30-line shim with identical read / seek / tell / close semantics so the
container adapters remain importable.
"""
from __future__ import annotations

try:
    from deepview.storage.filesystems._layer_io import LayerFileIO
except ImportError:  # pragma: no cover - fallback for partial trees
    import io
    import os
    from typing import BinaryIO

    from deepview.interfaces.layer import DataLayer

    class LayerFileIO(io.RawIOBase, BinaryIO):  # type: ignore[no-redef]
        """Minimal inline fallback — mirrors the filesystems shim."""

        def __init__(self, layer: DataLayer, offset: int = 0) -> None:
            super().__init__()
            self._layer = layer
            self._origin = int(offset)
            self._cursor = 0
            self._closed = False
            base_max = int(layer.maximum_address)
            base_min = int(layer.minimum_address)
            self._size = max(0, base_max - base_min - self._origin + 1)

        def readable(self) -> bool:
            return not self._closed

        def writable(self) -> bool:
            return False

        def seekable(self) -> bool:
            return not self._closed

        def read(self, size: int = -1) -> bytes:  # type: ignore[override]
            if self._closed:
                raise ValueError("I/O operation on closed LayerFileIO")
            if self._cursor >= self._size:
                return b""
            if size is None or size < 0:
                size = self._size - self._cursor
            remaining = self._size - self._cursor
            n = min(size, remaining)
            if n <= 0:
                return b""
            data = self._layer.read(self._origin + self._cursor, n, pad=True)
            if len(data) < n:
                data = data + b"\x00" * (n - len(data))
            self._cursor += n
            return bytes(data)

        def seek(self, pos: int, whence: int = os.SEEK_SET) -> int:  # type: ignore[override]
            if self._closed:
                raise ValueError("I/O operation on closed LayerFileIO")
            if whence == os.SEEK_SET:
                new = pos
            elif whence == os.SEEK_CUR:
                new = self._cursor + pos
            elif whence == os.SEEK_END:
                new = self._size + pos
            else:
                raise ValueError(f"invalid whence: {whence!r}")
            if new < 0:
                raise ValueError("negative seek position")
            self._cursor = new
            return self._cursor

        def tell(self) -> int:
            return self._cursor

        def close(self) -> None:
            self._closed = True
            super().close()

        def get_size(self) -> int:
            return self._size


__all__ = ["LayerFileIO"]
