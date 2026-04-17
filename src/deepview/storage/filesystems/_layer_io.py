"""File-like shim that wraps a :class:`DataLayer` for C-library backends.

Many forensic filesystem libraries (libtsk / libfsapfs / libfsntfs / libfsxfs /
libfsbtrfs / libfsf2fs / libfshfs / libfsext, …) accept a Python file-like
object with ``read / seek / tell / close`` semantics. :class:`LayerFileIO`
adapts an in-memory :class:`DataLayer` (raw, LiME, ELF-core, decrypted,
linearised flash, partition slice, etc.) to that contract without copying
the backing bytes.
"""
from __future__ import annotations

import io
import os

from deepview.interfaces.layer import DataLayer


class LayerFileIO(io.RawIOBase):
    """A seekable, read-only file-like view over a :class:`DataLayer`.

    Parameters
    ----------
    layer:
        Backing byte-addressable :class:`DataLayer`.
    offset:
        Logical origin inside the layer. All ``seek`` / ``tell`` values are
        relative to this offset — callers can slice a partition out of a
        whole-disk layer without recomputing offsets.
    """

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__()
        self._layer = layer
        self._origin = int(offset)
        self._cursor = 0
        self._closed = False
        base_max = int(layer.maximum_address)
        base_min = int(layer.minimum_address)
        # ``maximum_address`` semantics vary across layers — treat it as an
        # inclusive upper bound when strictly less than size, and use the
        # delta to the minimum as the usable size.
        self._size = max(0, base_max - base_min - self._origin + 1)

    # ------------------------------------------------------------------
    # RawIOBase contract
    # ------------------------------------------------------------------

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
        # Layers may return fewer bytes than requested at EOF — pad with \x00
        # rather than truncate, to satisfy libraries that strictly expect
        # ``len(result) == size``.
        if len(data) < n:
            data = data + b"\x00" * (n - len(data))
        self._cursor += n
        return bytes(data)

    def readall(self) -> bytes:
        return self.read(-1)

    def readinto(self, buffer: "bytearray | memoryview") -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        n = len(data)
        buffer[:n] = data
        return n

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

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def get_size(self) -> int:
        """Total addressable bytes; used by libraries such as libtsk."""
        return self._size

    def __len__(self) -> int:
        return self._size
