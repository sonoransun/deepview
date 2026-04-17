"""Pure-Python FAT12/FAT16 reader.

This is the one filesystem adapter that works without any optional extra —
it depends only on the standard library. It covers FAT12 and FAT16 with
short (8.3) names and the root-directory region present on pre-FAT32
volumes. LFN (VFAT) entries are surfaced only as their short-name
equivalents; FAT32 and exFAT are out of scope (use TSK or libfsxxx).

Deleted entries (first byte ``0xE5``) are reported with
``is_deleted=True`` when ``include_deleted=True`` is passed to
:meth:`FATFilesystem.list`.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.filesystem import Filesystem, FSEntry
from deepview.interfaces.layer import DataLayer
from deepview.storage.manager import StorageError

if TYPE_CHECKING:
    from collections.abc import Callable


ADAPTER_NAME = "fat"


@dataclass(frozen=True)
class _BootSector:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entry_count: int
    total_sectors: int
    sectors_per_fat: int
    fs_type: str  # "FAT12" or "FAT16"

    @property
    def fat_start(self) -> int:
        return self.reserved_sectors

    @property
    def root_dir_start(self) -> int:
        return self.reserved_sectors + self.num_fats * self.sectors_per_fat

    @property
    def root_dir_sectors(self) -> int:
        entries = self.root_entry_count
        # 32 bytes per directory entry, rounded up to sector
        bps = self.bytes_per_sector
        return ((entries * 32) + (bps - 1)) // bps

    @property
    def data_start(self) -> int:
        return self.root_dir_start + self.root_dir_sectors

    @property
    def total_clusters(self) -> int:
        data_sectors = self.total_sectors - self.data_start
        return data_sectors // self.sectors_per_cluster


def _parse_boot_sector(buf: bytes) -> _BootSector:
    if len(buf) < 64:
        raise StorageError("FAT boot sector too short")
    bps = struct.unpack_from("<H", buf, 11)[0]
    spc = buf[13]
    reserved = struct.unpack_from("<H", buf, 14)[0]
    num_fats = buf[16]
    root_entries = struct.unpack_from("<H", buf, 17)[0]
    total16 = struct.unpack_from("<H", buf, 19)[0]
    sectors_per_fat = struct.unpack_from("<H", buf, 22)[0]
    total32 = struct.unpack_from("<I", buf, 32)[0]
    total = total16 if total16 != 0 else total32
    if bps == 0 or spc == 0 or num_fats == 0 or sectors_per_fat == 0:
        raise StorageError("FAT boot sector fields invalid")
    # Compute FS type from cluster count (Microsoft's canonical rule).
    root_dir_sectors = ((root_entries * 32) + (bps - 1)) // bps
    data_sectors = total - (reserved + num_fats * sectors_per_fat + root_dir_sectors)
    count_of_clusters = data_sectors // spc if spc else 0
    if count_of_clusters < 4085:
        fs_type = "FAT12"
    elif count_of_clusters < 65525:
        fs_type = "FAT16"
    else:
        raise StorageError("FAT32 is not supported by fat_native; use TSK")
    return _BootSector(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        reserved_sectors=reserved,
        num_fats=num_fats,
        root_entry_count=root_entries,
        total_sectors=total,
        sectors_per_fat=sectors_per_fat,
        fs_type=fs_type,
    )


def _fat12_entry(fat: bytes, cluster: int) -> int:
    off = (cluster * 3) // 2
    if off + 1 >= len(fat):
        return 0xFFF
    lo, hi = fat[off], fat[off + 1]
    if cluster & 1:
        return ((hi << 4) | (lo >> 4)) & 0xFFF
    return ((hi & 0x0F) << 8) | lo


def _fat16_entry(fat: bytes, cluster: int) -> int:
    off = cluster * 2
    if off + 1 >= len(fat):
        return 0xFFFF
    return struct.unpack_from("<H", fat, off)[0]


def _is_end_of_chain(val: int, fs_type: str) -> bool:
    if fs_type == "FAT12":
        return val >= 0xFF8
    return val >= 0xFFF8


@dataclass(frozen=True)
class _DirEntry:
    name: str
    attr: int
    size: int
    start_cluster: int
    is_dir: bool
    is_deleted: bool
    mtime: float
    atime: float
    ctime: float


_ATTR_DIR = 0x10
_ATTR_VOL_ID = 0x08
_ATTR_LFN = 0x0F


def _decode_short_name(entry: bytes) -> str:
    base = entry[0:8].rstrip(b" ").decode("ascii", errors="replace")
    ext = entry[8:11].rstrip(b" ").decode("ascii", errors="replace")
    if ext:
        return f"{base}.{ext}"
    return base


def _parse_dir_entries(buf: bytes, *, include_deleted: bool) -> Iterator[_DirEntry]:
    for i in range(0, len(buf), 32):
        chunk = buf[i : i + 32]
        if len(chunk) < 32:
            break
        first = chunk[0]
        if first == 0x00:
            break  # end of directory
        attr = chunk[11]
        if attr == _ATTR_LFN:
            continue
        if attr & _ATTR_VOL_ID:
            continue
        is_deleted = first == 0xE5
        if is_deleted and not include_deleted:
            continue
        raw = chunk
        if is_deleted:
            raw = b"_" + chunk[1:]  # restore a placeholder first char for decode
        name = _decode_short_name(raw)
        attr_val = attr
        size = struct.unpack_from("<I", chunk, 28)[0]
        lo = struct.unpack_from("<H", chunk, 26)[0]
        hi = struct.unpack_from("<H", chunk, 20)[0]
        start_cluster = (hi << 16) | lo
        is_dir = bool(attr_val & _ATTR_DIR)
        # Time fields are DOS-encoded; decode approximately to epoch seconds.
        mtime = _decode_dos_time(
            struct.unpack_from("<H", chunk, 22)[0],
            struct.unpack_from("<H", chunk, 24)[0],
        )
        ctime = _decode_dos_time(
            struct.unpack_from("<H", chunk, 14)[0],
            struct.unpack_from("<H", chunk, 16)[0],
        )
        atime_date = struct.unpack_from("<H", chunk, 18)[0]
        atime = _decode_dos_time(0, atime_date)
        yield _DirEntry(
            name=name,
            attr=attr_val,
            size=size,
            start_cluster=start_cluster,
            is_dir=is_dir,
            is_deleted=is_deleted,
            mtime=mtime,
            atime=atime,
            ctime=ctime,
        )


def _decode_dos_time(time_field: int, date_field: int) -> float:
    """Convert (time, date) DOS fields to POSIX-ish epoch seconds.

    DOS epoch is 1980-01-01; we return seconds since Unix epoch. This is
    forensic-grade-adjacent — fine for reporting, not for legal-grade MAC
    timestamps where the operator should use the raw fields.
    """
    if date_field == 0:
        return 0.0
    import datetime

    year = 1980 + ((date_field >> 9) & 0x7F)
    month = max(1, (date_field >> 5) & 0x0F)
    day = max(1, date_field & 0x1F)
    hour = (time_field >> 11) & 0x1F
    minute = (time_field >> 5) & 0x3F
    second = (time_field & 0x1F) * 2
    try:
        dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    except ValueError:
        return 0.0
    return dt.timestamp()


class _FATFileLayer(DataLayer):
    """:class:`DataLayer` over a FAT file's cluster chain."""

    def __init__(self, fs: FATFilesystem, entry: _DirEntry, name: str) -> None:
        self._fs = fs
        self._entry = entry
        self._name = name
        self._size = entry.size

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or offset >= self._size:
            return b"\x00" * length if pad else b""
        end = min(offset + length, self._size)
        data = self._fs._read_chain(self._entry.start_cluster, offset, end - offset)
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("FAT native is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= self._size

    def scan(self, scanner: Any, progress_callback: "Callable[[float], None] | None" = None) -> Iterator[ScanResult]:
        buf = self.read(0, self._size)
        yield from scanner.scan(buf, offset=0)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, self._size - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name, minimum_address=0, maximum_address=max(0, self._size - 1))


class FATFilesystem(Filesystem):
    """Pure-Python FAT12 / FAT16 reader."""

    fs_name = "fat"

    def __init__(self, layer: DataLayer, offset: int = 0) -> None:
        super().__init__(layer, offset)
        boot = layer.read(offset, 512, pad=True)
        self._boot = _parse_boot_sector(boot)
        self.block_size = self._boot.bytes_per_sector
        # Read the primary FAT once and cache it.
        fat_bytes = self._boot.sectors_per_fat * self._boot.bytes_per_sector
        self._fat = bytes(
            layer.read(
                offset + self._boot.fat_start * self._boot.bytes_per_sector,
                fat_bytes,
                pad=True,
            )
        )

    @classmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool:
        try:
            buf = layer.read(offset, 512, pad=True)
        except Exception:
            return False
        if len(buf) < 512:
            return False
        # Boot sector signature.
        if buf[510] != 0x55 or buf[511] != 0xAA:
            return False
        try:
            _parse_boot_sector(buf)
        except StorageError:
            return False
        return True

    # ------------------------------------------------------------------
    # FAT / cluster helpers
    # ------------------------------------------------------------------

    def _fat_next(self, cluster: int) -> int:
        if self._boot.fs_type == "FAT12":
            return _fat12_entry(self._fat, cluster)
        return _fat16_entry(self._fat, cluster)

    def _cluster_offset(self, cluster: int) -> int:
        # Cluster 2 is the first data cluster.
        bps = self._boot.bytes_per_sector
        spc = self._boot.sectors_per_cluster
        base_sector = self._boot.data_start + (cluster - 2) * spc
        return self.offset + base_sector * bps

    def _cluster_size(self) -> int:
        return self._boot.sectors_per_cluster * self._boot.bytes_per_sector

    def _read_chain(self, start_cluster: int, offset: int, length: int) -> bytes:
        if start_cluster < 2 or length <= 0:
            return b""
        cluster_size = self._cluster_size()
        out = bytearray()
        cluster = start_cluster
        file_pos = 0
        while cluster >= 2 and not _is_end_of_chain(cluster, self._boot.fs_type):
            cluster_start = file_pos
            cluster_end = file_pos + cluster_size
            if cluster_end > offset and cluster_start < offset + length:
                local_off = max(0, offset - cluster_start)
                want = min(cluster_size - local_off, offset + length - (cluster_start + local_off))
                chunk = self.layer.read(
                    self._cluster_offset(cluster) + local_off,
                    want,
                    pad=True,
                )
                out.extend(chunk)
                if len(out) >= length:
                    break
            file_pos += cluster_size
            nxt = self._fat_next(cluster)
            if nxt == 0 or nxt == cluster:
                break
            cluster = nxt
            if file_pos >= offset + length:
                break
        return bytes(out[:length])

    def _read_root_dir(self) -> bytes:
        bps = self._boot.bytes_per_sector
        return bytes(
            self.layer.read(
                self.offset + self._boot.root_dir_start * bps,
                self._boot.root_dir_sectors * bps,
                pad=True,
            )
        )

    def _read_subdir(self, start_cluster: int) -> bytes:
        if start_cluster < 2:
            return b""
        out = bytearray()
        cluster = start_cluster
        seen: set[int] = set()
        while cluster >= 2 and not _is_end_of_chain(cluster, self._boot.fs_type):
            if cluster in seen:
                break
            seen.add(cluster)
            out.extend(
                self.layer.read(
                    self._cluster_offset(cluster),
                    self._cluster_size(),
                    pad=True,
                )
            )
            cluster = self._fat_next(cluster)
        return bytes(out)

    def _resolve(self, path: str) -> _DirEntry | None:
        if path in ("", "/"):
            return _DirEntry(
                name="/",
                attr=_ATTR_DIR,
                size=0,
                start_cluster=0,
                is_dir=True,
                is_deleted=False,
                mtime=0.0,
                atime=0.0,
                ctime=0.0,
            )
        components = [c for c in path.strip("/").split("/") if c]
        current_dir_bytes = self._read_root_dir()
        current: _DirEntry | None = None
        for i, comp in enumerate(components):
            last = i == len(components) - 1
            found: _DirEntry | None = None
            for e in _parse_dir_entries(current_dir_bytes, include_deleted=False):
                if e.name.upper() == comp.upper():
                    found = e
                    break
            if found is None:
                return None
            current = found
            if not last:
                if not found.is_dir:
                    return None
                current_dir_bytes = self._read_subdir(found.start_cluster)
        return current

    # ------------------------------------------------------------------
    # Filesystem interface
    # ------------------------------------------------------------------

    def _entry_to_fs(self, path: str, e: _DirEntry) -> FSEntry:
        return FSEntry(
            path=path,
            inode=e.start_cluster,
            size=e.size,
            mode=0o040755 if e.is_dir else 0o100644,
            uid=0,
            gid=0,
            mtime=e.mtime,
            atime=e.atime,
            ctime=e.ctime,
            is_dir=e.is_dir,
            is_symlink=False,
            is_deleted=e.is_deleted,
            extra={"fs": "fat", "attr": e.attr, "start_cluster": e.start_cluster},
        )

    def _walk_dir(
        self,
        dir_bytes: bytes,
        path: str,
        *,
        recursive: bool,
        include_deleted: bool,
    ) -> Iterator[FSEntry]:
        for e in _parse_dir_entries(dir_bytes, include_deleted=include_deleted):
            if e.name in (".", ".."):
                continue
            full = f"{path.rstrip('/')}/{e.name}" if path != "/" else f"/{e.name}"
            yield self._entry_to_fs(full, e)
            if recursive and e.is_dir and not e.is_deleted and e.start_cluster >= 2:
                sub = self._read_subdir(e.start_cluster)
                yield from self._walk_dir(
                    sub, full, recursive=True, include_deleted=include_deleted
                )

    def list(
        self,
        path: str = "/",
        *,
        recursive: bool = False,
        include_deleted: bool = False,
    ) -> Iterator[FSEntry]:
        if path in ("", "/"):
            dir_bytes = self._read_root_dir()
        else:
            target = self._resolve(path)
            if target is None or not target.is_dir:
                raise StorageError(f"FAT: not a directory: {path!r}")
            dir_bytes = self._read_subdir(target.start_cluster)
        yield from self._walk_dir(
            dir_bytes, path if path else "/", recursive=recursive, include_deleted=include_deleted
        )

    def stat(self, path: str) -> FSEntry:
        e = self._resolve(path)
        if e is None:
            raise StorageError(f"FAT: not found: {path!r}")
        return self._entry_to_fs(path, e)

    def open(self, path: str) -> DataLayer:
        e = self._resolve(path)
        if e is None or e.is_dir:
            raise StorageError(f"FAT: not a file: {path!r}")
        return _FATFileLayer(self, e, name=path)

    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes:
        e = self._resolve(path)
        if e is None or e.is_dir:
            raise StorageError(f"FAT: not a file: {path!r}")
        if length < 0:
            length = e.size - offset
        return self._read_chain(e.start_cluster, offset, max(0, length))


ADAPTER_CLASS = FATFilesystem


def register(manager: Any) -> None:
    manager.register_filesystem(ADAPTER_NAME, ADAPTER_CLASS)
