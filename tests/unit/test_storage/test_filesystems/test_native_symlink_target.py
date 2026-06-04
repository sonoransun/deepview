"""Symlink-target exposure tests for the native ``pyfsXXX`` adapters.

These adapters are thin wrappers around external libfs* C bindings that are
not installed in the core test environment, and whose real parsers cannot be
driven by a hand-built in-memory image. The *translation* layer, however, is
pure Python: ``_to_entry`` maps a duck-typed library file-entry object onto an
:class:`~deepview.interfaces.filesystem.FSEntry`.

We exercise that translation directly with fake file-entry objects (the same
duck-typing the real ``pyfsext`` / ``pyfsntfs`` / ... objects satisfy),
bypassing ``__init__`` (which would import the missing C library) via
``object.__new__``. This verifies the behaviour change in this lane:

* every adapter now populates ``FSEntry.target`` from the library's
  ``symbolic_link_target`` attribute, and
* ``ntfs_native`` no longer hardcodes ``is_symlink=False`` — it detects
  reparse-point symlinks like the POSIX adapters.
"""
from __future__ import annotations

import importlib
from typing import Any

import pytest

from deepview.interfaces.filesystem import Filesystem


class _FakeFileEntry:
    """Duck-typed stand-in for a libfs* file-entry object.

    Only the attributes ``_to_entry`` reads are provided; everything else is
    absent so the adapter's ``getattr(..., default)`` fallbacks are exercised.
    """

    def __init__(self, **attrs: Any) -> None:
        self.__dict__.update(attrs)


# (adapter module, class name) — every native adapter in this lane.
_ADAPTERS: tuple[tuple[str, str], ...] = (
    ("deepview.storage.filesystems.ext", "EXTFilesystem"),
    ("deepview.storage.filesystems.xfs", "XFSFilesystem"),
    ("deepview.storage.filesystems.btrfs", "BtrfsFilesystem"),
    ("deepview.storage.filesystems.f2fs", "F2FSFilesystem"),
    ("deepview.storage.filesystems.apfs", "APFSFilesystem"),
    ("deepview.storage.filesystems.ntfs_native", "NTFSFilesystem"),
)


def _adapter_class(adapter_mod: str, cls_name: str) -> type[Filesystem]:
    module = importlib.import_module(adapter_mod)
    return getattr(module, cls_name)  # type: ignore[no-any-return]


def _bare_instance(cls: type[Filesystem]) -> Filesystem:
    # Construct without running __init__ (which lazy-imports the missing
    # libfs* C binding); _to_entry only needs ``self`` for ``self._ads`` on
    # the NTFS adapter, which tolerates a file-entry lacking ADS attributes.
    return cls.__new__(cls)  # type: ignore[call-arg]


@pytest.mark.parametrize(("adapter_mod", "cls_name"), _ADAPTERS)
def test_symlink_target_is_exposed(adapter_mod: str, cls_name: str) -> None:
    cls = _adapter_class(adapter_mod, cls_name)
    fs = _bare_instance(cls)
    f = _FakeFileEntry(
        size=0,
        symbolic_link_target="/etc/real/target",
        number_of_sub_file_entries=0,
    )
    entry = fs._to_entry("/link", f)  # type: ignore[attr-defined]
    assert entry.is_symlink is True
    assert entry.target == "/etc/real/target"


@pytest.mark.parametrize(("adapter_mod", "cls_name"), _ADAPTERS)
def test_plain_file_has_no_target(adapter_mod: str, cls_name: str) -> None:
    cls = _adapter_class(adapter_mod, cls_name)
    fs = _bare_instance(cls)
    f = _FakeFileEntry(size=4096, number_of_sub_file_entries=0)
    entry = fs._to_entry("/file.bin", f)  # type: ignore[attr-defined]
    assert entry.is_symlink is False
    assert entry.target is None


@pytest.mark.parametrize(("adapter_mod", "cls_name"), _ADAPTERS)
def test_empty_target_string_is_not_a_symlink(
    adapter_mod: str, cls_name: str
) -> None:
    # An empty ``symbolic_link_target`` must not be reported as a symlink and
    # must not leak an empty-string target.
    cls = _adapter_class(adapter_mod, cls_name)
    fs = _bare_instance(cls)
    f = _FakeFileEntry(
        size=10,
        symbolic_link_target="",
        number_of_sub_file_entries=0,
    )
    entry = fs._to_entry("/x", f)  # type: ignore[attr-defined]
    assert entry.is_symlink is False
    assert entry.target is None


@pytest.mark.parametrize(("adapter_mod", "cls_name"), _ADAPTERS)
def test_directory_is_not_a_symlink(adapter_mod: str, cls_name: str) -> None:
    cls = _adapter_class(adapter_mod, cls_name)
    fs = _bare_instance(cls)
    f = _FakeFileEntry(size=0, number_of_sub_file_entries=3)
    entry = fs._to_entry("/dir", f)  # type: ignore[attr-defined]
    assert entry.is_dir is True
    assert entry.is_symlink is False
    assert entry.target is None


def test_ntfs_native_detects_reparse_symlink() -> None:
    """Regression: ntfs_native used to hardcode ``is_symlink=False``.

    A reparse-point file entry with a symlink target must now be reported as a
    symlink, and the reparse tag surfaced in ``extra`` for triage.
    """
    cls = _adapter_class(
        "deepview.storage.filesystems.ntfs_native", "NTFSFilesystem"
    )
    fs = _bare_instance(cls)
    f = _FakeFileEntry(
        size=0,
        file_reference=42,
        symbolic_link_target="C:\\Windows\\System32",
        reparse_point_tag=0xA000000C,  # IO_REPARSE_TAG_SYMLINK
        number_of_sub_file_entries=0,
    )
    entry = fs._to_entry("/junction", f)  # type: ignore[attr-defined]
    assert entry.is_symlink is True
    assert entry.target == "C:\\Windows\\System32"
    assert entry.extra["reparse_point_tag"] == 0xA000000C
    assert entry.extra["fs"] == "ntfs_native"


def test_ntfs_native_plain_file_omits_reparse_tag() -> None:
    cls = _adapter_class(
        "deepview.storage.filesystems.ntfs_native", "NTFSFilesystem"
    )
    fs = _bare_instance(cls)
    f = _FakeFileEntry(size=128, file_reference=7, number_of_sub_file_entries=0)
    entry = fs._to_entry("/plain.txt", f)  # type: ignore[attr-defined]
    assert entry.is_symlink is False
    assert entry.target is None
    assert "reparse_point_tag" not in entry.extra
    assert entry.inode == 7


def test_apfs_symlink_preserves_snapshot_and_extents() -> None:
    """The APFS-specific ``extra`` (snapshot/extents) survives the target wiring."""
    cls = _adapter_class("deepview.storage.filesystems.apfs", "APFSFilesystem")
    fs = _bare_instance(cls)
    f = _FakeFileEntry(
        size=0,
        identifier=99,
        symbolic_link_target="../sibling",
        snapshot_name="daily-2026-06-03",
        number_of_extents=0,
        number_of_sub_file_entries=0,
    )
    entry = fs._to_entry("/snap/link", f)  # type: ignore[attr-defined]
    assert entry.is_symlink is True
    assert entry.target == "../sibling"
    assert entry.extra["snapshot"] == "daily-2026-06-03"
    assert entry.extra["extents"] == []
    assert entry.inode == 99
