"""Network connection listing plugin — reconstructs TCP/UDP from memory."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="netstat",
    category=PluginCategory.NETWORK_ANALYSIS,
    description="List network connections from a memory image",
    tags=["network", "connections", "memory"],
)
class NetstatPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
            Requirement(
                name="os_hint",
                description="Target OS: windows, linux, or auto (default)",
                required=False,
                default="auto",
            ),
        ]

    def run(self) -> PluginResult:
        from pathlib import Path

        from deepview.memory.manager import MemoryManager
        from deepview.memory.network.tcp_reconstruct import TCPStackReconstructor

        image_path = self.config.get("image_path")
        if not image_path:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": "image_path is required"}],
            )

        os_hint = self.config.get("os_hint", "auto")

        mm = MemoryManager(self.context)
        layer = mm.open_layer(Path(image_path))
        reconstructor = TCPStackReconstructor(layer)
        connections = reconstructor.extract_connections(os_hint=os_hint)

        rows = []
        for conn in connections:
            rows.append({
                "Proto": conn.protocol.upper(),
                "LocalAddr": conn.local_addr,
                "LocalPort": str(conn.local_port),
                "RemoteAddr": conn.remote_addr,
                "RemotePort": str(conn.remote_port),
                "State": conn.state,
                "PID": str(conn.pid),
                "Process": conn.process_name,
            })

        return PluginResult(
            columns=[
                "Proto", "LocalAddr", "LocalPort",
                "RemoteAddr", "RemotePort", "State", "PID", "Process",
            ],
            rows=rows,
            metadata={"total_connections": len(rows)},
        )
