"""ZFS adapter — probe + uberblock metadata.

A full libzfs adapter is intentionally deferred: libzfs is not reliably
available cross-platform and would add several thousand LOC of code to
touch every on-disk structure (ZAP, compression, DMU object sets, the
full block-pointer chain). Instead this module surfaces *detection* plus
*pool identification* — it parses the active uberblock so the operator
knows which transaction group / SPA version a pool is at — while every
data-read call raises :class:`NotImplementedError` with a clear pointer
forward.

The probe looks for the ZFS uberblock magic ``0x00bab10c`` at the two
standard uberblock offsets inside the L0/L1 vdev label region
(``0x20000`` and ``0x21000``). These correspond to the second and third
kilobytes of the 256 KiB vdev label starting at byte 0 of a ZFS vdev.

An uberblock begins with five 64-bit fields followed by a 128-byte
``blkptr`` (the pool root, ``rootbp``)::

    uint64  ub_magic        (0x00bab10c, native or byteswapped)
    uint64  ub_version      (SPA on-disk version)
    uint64  ub_txg          (transaction group — newest active wins)
    uint64  ub_guid_sum     (sum of all vdev GUIDs in the pool)
    uint64  ub_timestamp    (UTC seconds of this txg's sync)
    blkptr  ub_rootbp       (128 bytes — not decoded here)

The active uberblock is the candidate slot holding the highest valid
``txg``; ZFS rotates writes across slots so the newest commit may live at
either probe offset.
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

# Five 64-bit header fields precede the 128-byte rootbp blkptr.
_UB_HEADER_FMT_LE = "<5Q"
_UB_HEADER_FMT_BE = ">5Q"
_UB_HEADER_LEN = struct.calcsize(_UB_HEADER_FMT_LE)  # 40 bytes


def _magic_endian(buf: bytes, offset: int = 0) -> str | None:
    """Return ``"le"`` / ``"be"`` if the 64-bit uberblock magic is at *offset*.

    The ``ub_magic`` field is a ``uint64`` written in the host's native byte
    order, so a foreign-endian pool surfaces the magic only under the swapped
    interpretation. Returns ``None`` when neither interpretation matches (or
    the region is too short for the 8-byte field).
    """
    if offset < 0 or len(buf) - offset < 8:
        return None
    le_q, = struct.unpack_from("<Q", buf, offset)
    if le_q == _ZFS_UBERBLOCK_MAGIC:
        return "le"
    be_q, = struct.unpack_from(">Q", buf, offset)
    if be_q == _ZFS_UBERBLOCK_MAGIC:
        return "be"
    return None


def _looks_like_uberblock(buf: bytes) -> bool:
    """Return ``True`` when *buf* (>=8 bytes) starts with the uberblock magic.

    Uberblocks may be written in either endianness depending on vdev host;
    check both 64-bit interpretations so probing succeeds on either.
    """
    return _magic_endian(buf, 0) is not None


def _parse_uberblock(buf: bytes, offset: int) -> dict[str, Any] | None:
    """Parse the uberblock header at *offset* within *buf*.

    Detects endianness from the 64-bit magic (the magic is written in the
    host's native byte order, so a byteswapped magic flags a foreign-endian
    pool). Returns a dict with ``version``, ``txg``, ``guid_sum``,
    ``timestamp`` and ``endian`` (``"le"`` / ``"be"``), or ``None`` when the
    region is too short or does not carry a valid uberblock magic.
    """
    if offset < 0 or len(buf) - offset < _UB_HEADER_LEN:
        return None
    endian = _magic_endian(buf, offset)
    if endian is None:
        return None
    fmt = _UB_HEADER_FMT_LE if endian == "le" else _UB_HEADER_FMT_BE
    magic, version, txg, guid_sum, timestamp = struct.unpack_from(fmt, buf, offset)
    if magic != _ZFS_UBERBLOCK_MAGIC:
        return None
    return {
        "version": version,
        "txg": txg,
        "guid_sum": guid_sum,
        "timestamp": timestamp,
        "endian": endian,
    }


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
    # Pool identification — parse the uberblock without decoding any data.
    # ------------------------------------------------------------------

    def active_uberblock(self) -> dict[str, Any] | None:
        """Return the parsed active (highest-txg) uberblock, or ``None``.

        Scans every candidate uberblock slot, parses each one defensively,
        and returns the slot carrying the highest valid transaction group —
        that is the most recently committed state of the pool.
        """
        best: dict[str, Any] | None = None
        for probe_off in _PROBE_OFFSETS:
            try:
                buf = self.layer.read(self.offset + probe_off, _UB_HEADER_LEN, pad=True)
            except Exception:
                continue
            ub = _parse_uberblock(buf, 0)
            if ub is None:
                continue
            if best is None or ub["txg"] > best["txg"]:
                best = ub
        return best

    def pool_metadata(self) -> dict[str, Any]:
        """Return a summary of the pool from its active uberblock.

        Always returns a dict; ``present`` is ``False`` (and the numeric
        fields are zeroed) when no uberblock parses.
        """
        ub = self.active_uberblock()
        if ub is None:
            return {
                "present": False,
                "txg": 0,
                "version": 0,
                "guid_sum": 0,
                "timestamp": 0,
                "endian": "le",
            }
        return {
            "present": True,
            "txg": ub["txg"],
            "version": ub["version"],
            "guid_sum": ub["guid_sum"],
            "timestamp": ub["timestamp"],
            "endian": ub["endian"],
        }

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
