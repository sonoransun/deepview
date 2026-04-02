from __future__ import annotations

from typing import Any

from deepview.core.types import Platform, PluginCategory, PluginMetadata

# Global registry of decorated plugins (populated at import time)
_REGISTERED_PLUGINS: dict[str, type] = {}


def register_plugin(
    name: str,
    category: PluginCategory = PluginCategory.CUSTOM,
    description: str = "",
    version: str = "0.1.0",
    author: str = "",
    tags: list[str] | None = None,
    platforms: list[Platform] | None = None,
):
    """Decorator to register a DeepViewPlugin subclass."""

    def decorator(cls):
        metadata = PluginMetadata(
            name=name,
            version=version,
            author=author,
            description=description,
            category=category,
            tags=tags or [],
            platforms=platforms or [Platform.LINUX, Platform.MACOS, Platform.WINDOWS],
        )
        cls._plugin_metadata = metadata
        _REGISTERED_PLUGINS[name] = cls

        # Override get_metadata to return our metadata
        original_get_metadata = getattr(cls, "get_metadata", None)

        @classmethod
        def get_metadata(klass) -> PluginMetadata:
            return klass._plugin_metadata

        cls.get_metadata = get_metadata

        return cls

    return decorator


def get_registered_plugins() -> dict[str, type]:
    """Return all plugins registered via @register_plugin."""
    return dict(_REGISTERED_PLUGINS)
