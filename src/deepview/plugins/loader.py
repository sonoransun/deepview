from __future__ import annotations

import importlib
import importlib.util
import os
import stat
import sys
from pathlib import Path

from deepview.core.exceptions import PluginLoadError
from deepview.core.logging import get_logger

log = get_logger("plugins.loader")


def _validate_plugin_file(path: Path) -> None:
    """Security checks before loading a plugin file.

    Raises PluginLoadError if the file fails validation.
    """
    resolved = path.resolve()

    # Reject symlinks — prevents TOCTOU and path misdirection attacks.
    if path.is_symlink():
        raise PluginLoadError(f"Refusing to load symlinked plugin: {path}")

    # On Unix, reject world-writable files (attacker could have modified them).
    if hasattr(os, "getuid"):
        try:
            st = resolved.stat()
            if st.st_mode & stat.S_IWOTH:
                raise PluginLoadError(
                    f"Refusing to load world-writable plugin: {resolved}"
                )
        except OSError as exc:
            raise PluginLoadError(f"Cannot stat plugin file {resolved}: {exc}") from exc


def load_module_from_path(path: Path) -> object | None:
    """Dynamically import a Python module from a file path."""
    if not path.exists() or not path.suffix == ".py":
        return None

    _validate_plugin_file(path)

    module_name = f"deepview.plugins.external.{path.stem}"
    log.warning(
        "loading_external_plugin",
        path=str(path.resolve()),
        module=module_name,
    )
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            log.warning("failed_to_create_module_spec", path=str(path))
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        log.info("loaded_plugin_module", path=str(path), module=module_name)
        return module
    except PluginLoadError:
        raise
    except Exception as e:
        log.error("plugin_load_failed", path=str(path), error=str(e))
        raise PluginLoadError(f"Failed to load plugin from {path}: {e}") from e


def load_module_by_name(module_name: str) -> object | None:
    """Import a module by its dotted name."""
    try:
        module = importlib.import_module(module_name)
        log.info("loaded_plugin_module", module=module_name)
        return module
    except Exception as e:
        log.error("plugin_load_failed", module=module_name, error=str(e))
        raise PluginLoadError(
            f"Failed to load plugin module {module_name}: {e}"
        ) from e
