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
        from pathlib import Path
        from deepview.memory.manager import MemoryManager
        from deepview.detection.encryption_keys import EncryptionKeyScanner

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        try:
            mm = MemoryManager(self.context)
            layer = mm.open_layer(Path(image_path))
            scanner = EncryptionKeyScanner()

            # Read first 64MB for scanning
            chunk_size = 64 * 1024 * 1024
            data = layer.read(
                layer.minimum_address,
                min(chunk_size, layer.maximum_address - layer.minimum_address),
            )
            findings = scanner.scan_all(data, offset=layer.minimum_address)

            rows = [
                {
                    "Type": f.key_type,
                    "Source": "memory",
                    "Username": "",
                    "Value": f.key_data[:16].hex(),
                    "Offset": f"0x{f.offset:x}",
                }
                for f in findings
            ]
            return PluginResult(
                columns=["Type", "Source", "Username", "Value", "Offset"],
                rows=rows,
                metadata={"total_findings": len(findings)},
            )
        except Exception as e:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": str(e)}],
            )
