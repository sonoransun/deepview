"""Unit tests for :class:`deepview.storage.manager.StorageManager`."""
from __future__ import annotations

import logging

import pytest

from tests._factories import MemoryDataLayer

from deepview.interfaces.filesystem import Filesystem
from deepview.storage.geometry import NANDGeometry
from deepview.storage.manager import StorageError, StorageManager


# ---------------------------------------------------------------------------
# Minimal Filesystem stubs — used to exercise registration & probe wiring
# without depending on any real fs adapter.
# ---------------------------------------------------------------------------


class _BaseFakeFS(Filesystem):
    """Common fake filesystem scaffolding; subclasses override ``probe``."""

    fs_name = "fake"

    def __init__(self, layer, offset: int = 0) -> None:  # type: ignore[no-untyped-def]
        super().__init__(layer, offset)

    @classmethod
    def probe(cls, layer, offset: int = 0) -> bool:  # type: ignore[no-untyped-def]
        return False

    def list(self, path="/", *, recursive=False, include_deleted=False):  # type: ignore[no-untyped-def]
        return iter(())

    def stat(self, path):  # type: ignore[no-untyped-def]
        raise FileNotFoundError(path)

    def open(self, path):  # type: ignore[no-untyped-def]
        raise FileNotFoundError(path)

    def read(self, path, offset=0, length=-1):  # type: ignore[no-untyped-def]
        raise FileNotFoundError(path)


class _NoProbeFS(_BaseFakeFS):
    """Probe-never-matches fake."""


class _MatchingFS(_BaseFakeFS):
    """Probe-always-matches fake."""

    @classmethod
    def probe(cls, layer, offset: int = 0) -> bool:  # type: ignore[no-untyped-def]
        return True


class _RaisingFS(_BaseFakeFS):
    """Probe raises a RuntimeError — must be logged & skipped, not fatal."""

    @classmethod
    def probe(cls, layer, offset: int = 0) -> bool:  # type: ignore[no-untyped-def]
        raise RuntimeError("synthetic probe failure")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_filesystems_list_is_populated(context) -> None:  # type: ignore[no-untyped-def]
    mgr = StorageManager(context)
    # register_all runs at construction; the always-available adapters
    # (fat_native, zfs) should at least populate the list.
    assert isinstance(mgr.filesystems(), list)


def test_register_filesystem_and_open_by_name(context) -> None:  # type: ignore[no-untyped-def]
    mgr = StorageManager(context)
    mgr.register_filesystem("fake", _NoProbeFS)
    layer = MemoryDataLayer(b"\x00" * 64)
    fs = mgr.open_filesystem(layer, fs_type="fake")
    assert isinstance(fs, _NoProbeFS)
    assert fs.layer is layer
    assert fs.offset == 0


def test_open_filesystem_auto_probe_raises_when_no_match(context) -> None:  # type: ignore[no-untyped-def]
    mgr = StorageManager(context)
    # Strip any auto-registered adapters so the iteration yields nothing.
    mgr._fs_adapters.clear()
    mgr.register_filesystem("fake", _NoProbeFS)
    layer = MemoryDataLayer(b"\x00" * 64)
    with pytest.raises(StorageError):
        mgr.open_filesystem(layer)


def test_open_filesystem_auto_picks_first_matching_adapter(
    context,  # type: ignore[no-untyped-def]
) -> None:
    mgr = StorageManager(context)
    mgr._fs_adapters.clear()
    mgr.register_filesystem("nope", _NoProbeFS)
    mgr.register_filesystem("yes", _MatchingFS)
    layer = MemoryDataLayer(b"\x00" * 64)
    fs = mgr.open_filesystem(layer)
    assert isinstance(fs, _MatchingFS)


def test_probe_lists_only_matching_adapters(context) -> None:  # type: ignore[no-untyped-def]
    mgr = StorageManager(context)
    mgr._fs_adapters.clear()
    mgr.register_filesystem("nope", _NoProbeFS)
    mgr.register_filesystem("yes", _MatchingFS)
    layer = MemoryDataLayer(b"\x00" * 64)
    hits = mgr.probe(layer)
    assert hits == ["filesystem:yes"]


def test_probe_swallows_runtime_errors_and_logs(
    context,  # type: ignore[no-untyped-def]
    caplog: pytest.LogCaptureFixture,
) -> None:
    mgr = StorageManager(context)
    mgr._fs_adapters.clear()
    mgr.register_filesystem("bad", _RaisingFS)
    mgr.register_filesystem("yes", _MatchingFS)
    layer = MemoryDataLayer(b"\x00" * 64)
    with caplog.at_level(logging.INFO, logger="deepview.storage.manager"):
        hits = mgr.probe(layer)
    assert hits == ["filesystem:yes"]
    # The bad probe emits an INFO-level skip message; make sure it did.
    assert any("bad" in rec.getMessage() for rec in caplog.records)


def test_open_filesystem_skips_raising_probe(
    context,  # type: ignore[no-untyped-def]
    caplog: pytest.LogCaptureFixture,
) -> None:
    mgr = StorageManager(context)
    mgr._fs_adapters.clear()
    mgr.register_filesystem("bad", _RaisingFS)
    mgr.register_filesystem("yes", _MatchingFS)
    layer = MemoryDataLayer(b"\x00" * 64)
    with caplog.at_level(logging.INFO, logger="deepview.storage.manager"):
        fs = mgr.open_filesystem(layer)
    assert isinstance(fs, _MatchingFS)


def test_unknown_fs_type_raises_storage_error(context) -> None:  # type: ignore[no-untyped-def]
    mgr = StorageManager(context)
    layer = MemoryDataLayer(b"\x00" * 64)
    with pytest.raises(StorageError):
        mgr.open_filesystem(layer, fs_type="does-not-exist")


def test_wrap_nand_without_ecc_or_ftl_returns_layer_unchanged(
    context,  # type: ignore[no-untyped-def]
) -> None:
    mgr = StorageManager(context)
    layer = MemoryDataLayer(b"\x00" * 2048)
    geometry = NANDGeometry(
        page_size=2048, spare_size=64, pages_per_block=64, blocks=16
    )
    wrapped = mgr.wrap_nand(layer, geometry)
    assert wrapped is layer
