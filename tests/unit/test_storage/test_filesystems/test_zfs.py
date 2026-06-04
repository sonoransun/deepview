"""Tests for the ZFS probe-only skeleton adapter."""
from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.filesystems.zfs import ZFSFilesystem, _parse_uberblock


class _MemoryDataLayer(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0:
            return b"\x00" * length if pad else b""
        end = min(offset + length, len(self._data))
        out = self._data[offset:end]
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self, scanner: object, progress_callback: Callable | None = None
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._data) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name="zfs-test")


_PROBE_OFFSETS = (0x20000, 0x21000)


def _make_zfs_blob(magic_offset: int) -> bytes:
    """Build a file with the ZFS uberblock magic at *magic_offset*."""
    size = magic_offset + 4096
    buf = bytearray(size)
    struct.pack_into("<I", buf, magic_offset, 0x00BAB10C)
    return bytes(buf)


def _make_uberblock(
    txg: int,
    *,
    version: int = 5000,
    guid_sum: int = 0,
    timestamp: int = 0,
    little_endian: bool = True,
) -> bytes:
    """Pack a 40-byte ZFS uberblock header (5 x uint64)."""
    fmt = "<5Q" if little_endian else ">5Q"
    return struct.pack(fmt, 0x00BAB10C, version, txg, guid_sum, timestamp)


def _make_zfs_pool_blob(
    slots: dict[int, bytes],
    *,
    size: int | None = None,
) -> bytes:
    """Build a label blob writing each uberblock *slots[offset]* in place."""
    end = size if size is not None else max(slots) + 4096
    buf = bytearray(end)
    for off, ub in slots.items():
        buf[off : off + len(ub)] = ub
    return bytes(buf)


class TestZFSProbe:
    def test_probe_detects_magic_at_first_uberblock_offset(self, tmp_path: Path) -> None:
        data = _make_zfs_blob(0x20000)
        layer = _MemoryDataLayer(data)
        assert ZFSFilesystem.probe(layer) is True

    def test_probe_detects_magic_at_second_uberblock_offset(self) -> None:
        data = _make_zfs_blob(0x21000)
        layer = _MemoryDataLayer(data)
        assert ZFSFilesystem.probe(layer) is True

    def test_probe_rejects_zero_bytes(self) -> None:
        layer = _MemoryDataLayer(b"\x00" * 0x30000)
        assert ZFSFilesystem.probe(layer) is False


class TestZFSNotWired:
    """Every operation past probe should raise :class:`NotImplementedError`."""

    @pytest.fixture
    def fs(self) -> ZFSFilesystem:
        data = _make_zfs_blob(0x20000)
        return ZFSFilesystem(_MemoryDataLayer(data))

    def test_list_raises_not_implemented(self, fs: ZFSFilesystem) -> None:
        with pytest.raises(NotImplementedError, match="ZFS"):
            list(fs.list("/"))

    def test_stat_raises_not_implemented(self, fs: ZFSFilesystem) -> None:
        with pytest.raises(NotImplementedError, match="ZFS"):
            fs.stat("/anything")

    def test_open_raises_not_implemented(self, fs: ZFSFilesystem) -> None:
        with pytest.raises(NotImplementedError, match="ZFS"):
            fs.open("/anything")

    def test_read_raises_not_implemented(self, fs: ZFSFilesystem) -> None:
        with pytest.raises(NotImplementedError, match="ZFS"):
            fs.read("/anything")


class TestZFSUberblock:
    """Active-uberblock parsing and pool-metadata exposure."""

    def test_parses_active_uberblock_at_first_slot(self) -> None:
        ub = _make_uberblock(
            txg=4242, version=5000, guid_sum=0xDEADBEEFCAFE, timestamp=1717372800
        )
        data = _make_zfs_pool_blob({_PROBE_OFFSETS[0]: ub})
        fs = ZFSFilesystem(_MemoryDataLayer(data))

        active = fs.active_uberblock()
        assert active is not None
        assert active["txg"] == 4242
        assert active["version"] == 5000
        assert active["guid_sum"] == 0xDEADBEEFCAFE
        assert active["timestamp"] == 1717372800
        assert active["endian"] == "le"

    def test_pool_metadata_reports_present_fields(self) -> None:
        ub = _make_uberblock(
            txg=99, version=28, guid_sum=0x1122334455667788, timestamp=1234567890
        )
        data = _make_zfs_pool_blob({_PROBE_OFFSETS[1]: ub})
        fs = ZFSFilesystem(_MemoryDataLayer(data))

        meta = fs.pool_metadata()
        assert meta == {
            "present": True,
            "txg": 99,
            "version": 28,
            "guid_sum": 0x1122334455667788,
            "timestamp": 1234567890,
            "endian": "le",
        }

    def test_higher_txg_slot_wins(self) -> None:
        older = _make_uberblock(txg=10, version=5000, timestamp=1000)
        newer = _make_uberblock(txg=2000, version=5000, timestamp=2000)
        data = _make_zfs_pool_blob(
            {_PROBE_OFFSETS[0]: older, _PROBE_OFFSETS[1]: newer}
        )
        fs = ZFSFilesystem(_MemoryDataLayer(data))

        active = fs.active_uberblock()
        assert active is not None
        assert active["txg"] == 2000
        assert active["timestamp"] == 2000
        assert fs.pool_metadata()["txg"] == 2000

    def test_higher_txg_wins_regardless_of_slot_order(self) -> None:
        # Newest commit lives in the *first* slot this time.
        newer = _make_uberblock(txg=5555, version=5000, timestamp=9000)
        older = _make_uberblock(txg=3, version=5000, timestamp=10)
        data = _make_zfs_pool_blob(
            {_PROBE_OFFSETS[0]: newer, _PROBE_OFFSETS[1]: older}
        )
        fs = ZFSFilesystem(_MemoryDataLayer(data))

        assert fs.pool_metadata()["txg"] == 5555

    def test_parses_big_endian_uberblock(self) -> None:
        ub = _make_uberblock(
            txg=7, version=5000, guid_sum=0xABCD, timestamp=42, little_endian=False
        )
        data = _make_zfs_pool_blob({_PROBE_OFFSETS[0]: ub})
        fs = ZFSFilesystem(_MemoryDataLayer(data))

        meta = fs.pool_metadata()
        assert meta["present"] is True
        assert meta["txg"] == 7
        assert meta["guid_sum"] == 0xABCD
        assert meta["endian"] == "be"

    def test_pool_metadata_absent_on_blank_buffer(self) -> None:
        layer = _MemoryDataLayer(b"\x00" * 0x30000)
        fs = ZFSFilesystem(layer)

        assert fs.active_uberblock() is None
        meta = fs.pool_metadata()
        assert meta["present"] is False
        assert meta["txg"] == 0
        assert meta["version"] == 0
        assert meta["guid_sum"] == 0
        assert meta["timestamp"] == 0

    def test_parse_uberblock_none_on_short_buffer(self) -> None:
        # _parse_uberblock is defensive against a header shorter than 40 bytes.
        short = struct.pack("<I", 0x00BAB10C) + b"\x00" * 4  # 8 bytes, magic only
        assert _parse_uberblock(short, 0) is None

    def test_parse_uberblock_none_on_bad_magic(self) -> None:
        bogus = struct.pack("<5Q", 0xFFFFFFFF, 5000, 1, 0, 0)
        assert _parse_uberblock(bogus, 0) is None

    def test_parse_uberblock_none_on_negative_offset(self) -> None:
        assert _parse_uberblock(b"\x00" * 64, -1) is None
