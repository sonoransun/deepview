"""ZFS adapter — probe-only skeleton.

A full libzfs adapter is intentionally deferred: libzfs is not reliably
available cross-platform and would add several thousand LOC of code to
touch every on-disk structure. Instead this module surfaces *detection*
so the operator knows a ZFS pool is present, and any downstream call
raises :class:`NotImplementedError` with a clear pointer forward.

The probe looks for the ZFS uberblock magic ``0x00bab10c`` at the two
standard uberblock offsets inside the L0/L1 vdev label region
(``0x20000`` and ``0x21000``). These correspond to the second and third
kilobytes of the 256 KiB vdev label starting at byte 0 of a ZFS vdev.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import Any

from deepview.interfaces.filesystem import Filesystem, FSEntry
from deepview.interfaces.layer import DataLayer


ADAPTER_NAME = "zfs"

_ZFS_UBERBLOCK_MAGIC = 0x00BAB10C
_PROBE_OFFSETS: tuple[int, ...] = (0x20000, 0x21000)


def _looks_like_uberblock(buf: bytes) -> bool:
    """Return ``True`` when *buf* (>=4 bytes) starts with the uberblock magic.

    Uberblocks may be written in either endianness depending on vdev host;
    check both so probing succeeds on either.
    """
    if len(buf) < 4:
        return False
    le, = struct.unpack_from("<I", buf, 0)
    be, = struct.unpack_from(">I", buf, 0)
    return le == _ZFS_UBERBLOCK_MAGIC or be == _ZFS_UBERBLOCK_MAGIC


class ZFSFilesystem(Filesystem):
    """Detects the presence of a ZFS pool; no structural access is wired."""

    fs_name = "zfs"

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)

    @classmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        for probe_off in _PROBE_OFFSETS:
            try:
                buf = layer.read(offset + probe_off, 8, pad=True)
            except Exception:
                continue
            if _looks_like_uberblock(buf):
                return True
        return False

    # ------------------------------------------------------------------
    # All other operations intentionally raise — operators get a clear
    # message rather than a half-working read.
    # ------------------------------------------------------------------

    _NOT_WIRED = (
        "ZFS adapter not yet wired; libzfs cross-platform support is complex. "
        "Probe-only."
    )

    def list(
        self,
        path: str = "/",
        *,
        recursive: bool = False,
        include_deleted: bool = False,
    ) -> Iterator[FSEntry]:
        raise NotImplementedError(self._NOT_WIRED)

    def stat(self, path: str) -> FSEntry:
        raise NotImplementedError(self._NOT_WIRED)

    def open(self, path: str) -> DataLayer:
        raise NotImplementedError(self._NOT_WIRED)

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        raise NotImplementedError(self._NOT_WIRED)


ADAPTER_CLASS = ZFSFilesystem


def register(manager: Any) -> None:
    manager.register_filesystem(ADAPTER_NAME, ADAPTER_CLASS)
