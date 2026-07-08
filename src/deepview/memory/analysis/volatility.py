"""Volatility 3 analysis engine integration."""
from __future__ import annotations
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger
from deepview.interfaces.analysis import AnalysisEngine
from deepview.interfaces.layer import DataLayer

log = get_logger("memory.analysis.volatility")


class VolatilityEngine(AnalysisEngine):
    """Analysis engine wrapping Volatility 3 as a library."""

    def __init__(self):
        self._vol3 = None
        self._available = False
        try:
            import volatility3.framework
            import volatility3.plugins
            import volatility3.framework.automagic
            import volatility3.framework.contexts
            self._vol3 = volatility3
            volatility3.framework.require_interface_version(2, 0, 0)
            self._available = True
            log.info("volatility3_loaded")
        except ImportError:
            log.debug("volatility3_not_installed")
        except Exception as e:
            log.warning("volatility3_init_failed", error=str(e))

    @classmethod
    def engine_name(cls) -> str:
        return "volatility"

    def is_available(self) -> bool:
        return self._available

    def open_image(self, path: Path) -> DataLayer:
        """Open a memory image through Volatility 3's layer system."""
        if not self._available:
            raise RuntimeError("Volatility 3 is not available")

        from deepview.memory.formats.raw import RawMemoryLayer
        return RawMemoryLayer(path)

    def run_plugin(self, plugin_name: str, layer: DataLayer, **kwargs: Any) -> Any:
        """Run a Volatility 3 plugin on a memory image.

        For full integration, this creates a Volatility context, adds the
        appropriate layers and automagics, and runs the specified plugin.
        """
        if not self._available:
            raise RuntimeError("Volatility 3 is not available")

        vol3 = self._vol3
        from volatility3 import framework
        from volatility3.framework import automagic, contexts, interfaces
        from volatility3.framework.plugins import construct_plugin

        # Create a fresh context
        ctx = contexts.Context()

        # If layer has a path, use Volatility's own layer loading
        if hasattr(layer, '_path'):
            single_location = "file://" + str(layer._path)
            ctx.config["automagic.LayerStacker.single_location"] = single_location

        # Resolve the plugin *class* (construct_plugin requires the type, not a
        # name string). Accept both bare ("pslist") and fully-qualified names.
        fq_name = plugin_name if "." in plugin_name else vol3.plugins.__name__ + "." + plugin_name
        framework.import_files(vol3.plugins, True)
        plugin_classes = {
            p.__module__ + "." + p.__name__: p
            for p in interfaces.plugins.PluginInterface.get_children()
        }
        plugin_cls = plugin_classes.get(fq_name)
        if plugin_cls is None:
            # Fall back to a suffix match on the short name (e.g. ".pslist").
            suffix = "." + plugin_name.rsplit(".", 1)[-1]
            matches = [cls for name, cls in plugin_classes.items() if name.endswith(suffix)]
            if len(matches) == 1:
                plugin_cls = matches[0]
        if plugin_cls is None:
            raise RuntimeError(f"Volatility 3 plugin not found: {plugin_name}")

        # Apply caller-supplied options to the plugin's config subtree.
        base_config_path = "plugins"
        plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin_cls.__name__)
        for key, value in kwargs.items():
            ctx.config[interfaces.configuration.path_join(plugin_config_path, key)] = value

        # Run automagics against the resolved plugin, then construct and run it.
        available_automagics = automagic.available(ctx)
        automagics_list = automagic.choose_automagic(available_automagics, plugin_cls)
        plugin = construct_plugin(ctx, automagics_list, plugin_cls, base_config_path, None, None)

        result = plugin.run()
        log.info("plugin_completed", plugin=fq_name)
        return result

    def list_plugins(self) -> list[str]:
        """List all available Volatility 3 plugins."""
        if not self._available:
            return []

        try:
            from volatility3 import framework
            from volatility3.framework import interfaces

            framework.import_files(self._vol3.plugins, True)
            # Plugin classes are not orderable; sort by fully-qualified name.
            plugin_list = sorted(
                interfaces.plugins.PluginInterface.get_children(),
                key=lambda p: p.__module__ + "." + p.__name__,
            )
            return [p.__module__ + "." + p.__name__ for p in plugin_list]
        except Exception as e:
            log.warning("list_plugins_failed", error=str(e))
            return []
