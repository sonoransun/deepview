"""Bulk registration of all filesystem adapters with a :class:`StorageManager`.

Each adapter module declares a module-level ``register(manager)`` free
function. Importing some adapters may fail if an optional native extra
(`pytsk3`, `pyfsapfs`, `pyfsntfs`, `pyfsxfs`, `pyfsbtrfs`, `pyfsf2fs`,
`pyfshfs`, `pyfsext`) isn't installed — those are caught and skipped so
core installs remain importable.

Two adapters are always registered because they have no optional deps:

* ``fat`` — pure-Python FAT12/16 reader.
* ``zfs`` — probe-only skeleton.
"""
from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from deepview.storage.manager import StorageManager


logger = logging.getLogger(__name__)


# Ordered so that the always-available adapters come first. When the
# storage manager auto-probes a layer, the iteration order matches the
# insertion order — prefer the pure-Python fallback last so native
# adapters win when they're installed.
_ADAPTER_MODULES: tuple[str, ...] = (
    "deepview.storage.filesystems.fat_native",
    "deepview.storage.filesystems.zfs",
    "deepview.storage.filesystems.tsk",
    "deepview.storage.filesystems.apfs",
    "deepview.storage.filesystems.ntfs_native",
    "deepview.storage.filesystems.xfs",
    "deepview.storage.filesystems.btrfs",
    "deepview.storage.filesystems.f2fs",
    "deepview.storage.filesystems.hfs",
    "deepview.storage.filesystems.ext",
)


def register_all(manager: StorageManager) -> None:
    """Import every adapter module and register it with *manager*.

    Each import is guarded — a missing optional dep is a soft skip with
    a debug log entry, never a hard failure.
    """
    for mod_name in _ADAPTER_MODULES:
        try:
            module = importlib.import_module(mod_name)
        except Exception as exc:  # pragma: no cover - optional-dep path
            logger.debug("filesystem adapter %s not importable: %s", mod_name, exc)
            continue
        register_fn = getattr(module, "register", None)
        if register_fn is None:
            logger.debug("filesystem adapter %s missing register()", mod_name)
            continue
        try:
            register_fn(manager)
        except Exception as exc:  # pragma: no cover - adapter bug
            logger.debug("filesystem adapter %s register() failed: %s", mod_name, exc)
