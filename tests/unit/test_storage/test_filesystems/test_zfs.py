"""Tests for the ZFS probe-only skeleton adapter."""
from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.filesystems.zfs import ZFSFilesystem


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


def _make_zfs_blob(magic_offset: int) -> bytes:
    """Build a file with the ZFS uberblock magic at *magic_offset*."""
    size = magic_offset + 4096
    buf = bytearray(size)
    struct.pack_into("<I", buf, magic_offset, 0x00BAB10C)
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
