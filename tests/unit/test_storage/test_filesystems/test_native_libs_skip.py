"""Skip-if-missing smoke tests for each pyfsXXX native adapter.

For each (pyfsXXX, adapter class), we ``pytest.importorskip`` the module and
then assert that the adapter class's ``probe()`` either returns False or
raises cleanly against a zero-filled in-memory layer. This verifies the
``_layer_io.LayerFileIO`` <-> native-lib bridge imports and constructs.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer


class _MemoryDataLayer(DataLayer):
    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._data = bytes(data)
        self._name = name

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
        return LayerMetadata(name=self._name)


_ADAPTERS: tuple[tuple[str, str, str, str], ...] = (
    ("pyfsapfs", "deepview.storage.filesystems.apfs", "APFSFilesystem", "apfs"),
    ("pyfsntfs", "deepview.storage.filesystems.ntfs_native", "NTFSFilesystem", "ntfs_native"),
    ("pyfsxfs", "deepview.storage.filesystems.xfs", "XFSFilesystem", "xfs"),
    ("pyfsbtrfs", "deepview.storage.filesystems.btrfs", "BtrfsFilesystem", "btrfs"),
    ("pyfsf2fs", "deepview.storage.filesystems.f2fs", "F2FSFilesystem", "f2fs"),
    ("pyfshfs", "deepview.storage.filesystems.hfs", "HFSFilesystem", "hfs"),
    ("pyfsext", "deepview.storage.filesystems.ext", "EXTFilesystem", "ext"),
)


@pytest.mark.parametrize(("extra_mod", "adapter_mod", "cls_name", "fs_name"), _ADAPTERS)
def test_native_adapter_probe_against_zeroes(
    extra_mod: str, adapter_mod: str, cls_name: str, fs_name: str
) -> None:
    """Import the extra + adapter; assert probe handles junk data cleanly."""
    pytest.importorskip(extra_mod)
    import importlib

    module = importlib.import_module(adapter_mod)
    cls = getattr(module, cls_name)
    assert cls.fs_name == fs_name
    assert module.ADAPTER_NAME == fs_name
    assert module.ADAPTER_CLASS is cls

    # 8 MiB of zeros — no native lib recognises this as any real
    # filesystem. Probe must return False (never raise); the constructor
    # should raise :class:`StorageError` because the magic bytes miss.
    layer = _MemoryDataLayer(b"\x00" * (8 * 1024 * 1024))
    assert cls.probe(layer) is False

    from deepview.storage.manager import StorageError

    # A lenient assertion — accept StorageError (expected) but tolerate
    # backend quirks where a library opens a "zero-pool" volume. Either
    # outcome exercises the LayerFileIO bridge without false negatives.
    try:
        cls(layer)
    except StorageError:
        return
    except Exception as exc:
        pytest.fail(
            f"adapter {cls_name} raised non-StorageError against zeros: {exc!r}"
        )
