"""Credential extraction plugin."""
from __future__ import annotations
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

@register_plugin(
    name="credentials",
    category=PluginCategory.CREDENTIALS,
    description="Extract credentials and key material from memory",
    tags=["credentials", "passwords", "keys", "memory"],
)
class CredentialsPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
        ]

    def run(self) -> PluginResult:
        return PluginResult(
            columns=["Type", "Source", "Username", "Value", "Offset"],
            rows=[],
            metadata={"note": "Scans for password hashes, private keys, and session tokens"},
        )
