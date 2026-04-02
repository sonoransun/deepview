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
        from volatility3.framework import contexts, automagic
        from volatility3.framework.plugins import construct_plugin

        # Create a fresh context
        ctx = contexts.Context()

        # If layer has a path, use Volatility's own layer loading
        if hasattr(layer, '_path'):
            single_location = "file://" + str(layer._path)
            ctx.config["automagic.LayerStacker.single_location"] = single_location

        # Run automagics
        available_automagics = automagic.available(ctx)
        automagics_list = automagic.choose_automagic(available_automagics,
                                                       vol3.plugins.__name__ + "." + plugin_name)

        # Construct and run the plugin
        plugin = construct_plugin(ctx, automagics_list,
                                   vol3.plugins.__name__ + "." + plugin_name,
                                   None, None, None)

        result = plugin.run()
        log.info("plugin_completed", plugin=plugin_name)
        return result

    def list_plugins(self) -> list[str]:
        """List all available Volatility 3 plugins."""
        if not self._available:
            return []

        try:
            import volatility3.framework.plugins
            from volatility3.framework import interfaces

            failures = volatility3.framework.import_files(volatility3.plugins, True)
            plugin_list = sorted(
                interfaces.plugins.PluginInterface.get_children()
            )
            return [p.__module__ + "." + p.__name__ for p in plugin_list]
        except Exception as e:
            log.warning("list_plugins_failed", error=str(e))
            return []
