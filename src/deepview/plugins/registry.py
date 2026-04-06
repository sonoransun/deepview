from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.exceptions import PluginNotFoundError
from deepview.core.logging import get_logger
from deepview.core.types import PluginCategory, PluginMetadata
from deepview.plugins import loader
from deepview.plugins.base import get_registered_plugins

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.interfaces.plugin import DeepViewPlugin

log = get_logger("plugins.registry")

ENTRY_POINT_GROUP = "deepview.plugins"


class PluginRegistry:
    """Central plugin registry with three-tier discovery."""

    def __init__(self, context: AnalysisContext):
        self._context = context
        self._plugins: dict[str, type[DeepViewPlugin]] = {}
        self._discovered = False

    def discover(self) -> None:
        """Run all three discovery tiers."""
        if self._discovered:
            return
        self._discover_builtin()
        self._discover_entrypoints()
        self._discover_directory()
        self._discovered = True
        log.info("plugin_discovery_complete", count=len(self._plugins))

    def _discover_builtin(self) -> None:
        """Tier 1: Import builtin plugins to trigger @register_plugin decorators."""
        try:
            import deepview.plugins.builtin  # noqa: F401
        except ImportError:
            log.debug("no_builtin_plugins")

        for name, cls in get_registered_plugins().items():
            if name in self._plugins:
                log.warning("duplicate_plugin_name", name=name, replaced_by=cls.__name__)
            self._plugins[name] = cls
            log.debug("registered_builtin_plugin", name=name)

    def _discover_entrypoints(self) -> None:
        """Tier 2: Discover plugins via Python entry points."""
        try:
            eps = importlib.metadata.entry_points()
            plugin_eps = (
                eps.select(group=ENTRY_POINT_GROUP)
                if hasattr(eps, "select")
                else eps.get(ENTRY_POINT_GROUP, [])
            )
        except Exception as e:
            log.warning("entrypoint_discovery_failed", error=str(e))
            plugin_eps = []

        for ep in plugin_eps:
            try:
                plugin_cls = ep.load()
                name = ep.name
                if name in self._plugins:
                    log.warning("duplicate_plugin_name", name=name, replaced_by=plugin_cls.__name__)
                self._plugins[name] = plugin_cls
                log.debug("registered_entrypoint_plugin", name=name)
            except Exception as e:
                log.warning(
                    "entrypoint_plugin_load_failed", name=ep.name, error=str(e)
                )

    def _discover_directory(self) -> None:
        """Tier 3: Discover plugins from directory paths."""
        plugin_paths = self._context.config.plugin_paths

        # Also check default user plugin dir
        user_plugin_dir = self._context.config.config_dir / "plugins"
        if user_plugin_dir.exists():
            plugin_paths = [str(user_plugin_dir)] + plugin_paths

        for path_str in plugin_paths:
            path = Path(path_str).expanduser().resolve()
            if path.is_symlink():
                log.warning("refusing_symlink_plugin_dir", path=str(path))
                continue
            if not path.is_dir():
                continue
            for py_file in sorted(path.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                try:
                    loader.load_module_from_path(py_file)
                except Exception as e:
                    log.warning("directory_plugin_load_failed", file=str(py_file), error=str(e))

        # Pick up any newly registered plugins
        for name, cls in get_registered_plugins().items():
            if name not in self._plugins:
                self._plugins[name] = cls

    def register(self, name: str, plugin_cls: type[DeepViewPlugin]) -> None:
        """Manually register a plugin class."""
        self._plugins[name] = plugin_cls
        log.info("registered_plugin", name=name)

    def get(self, name: str) -> type[DeepViewPlugin]:
        """Get a plugin class by name."""
        self.discover()
        if name not in self._plugins:
            raise PluginNotFoundError(f"Plugin not found: {name}")
        return self._plugins[name]

    def list_plugins(
        self, category: PluginCategory | None = None
    ) -> list[PluginMetadata]:
        """List all discovered plugins, optionally filtered by category."""
        self.discover()
        results = []
        for name, cls in self._plugins.items():
            try:
                meta = cls.get_metadata()
                if category is None or meta.category == category:
                    results.append(meta)
            except Exception:
                results.append(PluginMetadata(name=name))
        return results

    def instantiate(
        self, name: str, config: dict | None = None
    ) -> DeepViewPlugin:
        """Create an instance of a plugin."""
        cls = self.get(name)
        return cls(context=self._context, config=config)

    @property
    def plugin_count(self) -> int:
        self.discover()
        return len(self._plugins)
