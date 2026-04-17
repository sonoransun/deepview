"""Register a custom :class:`DeepViewPlugin` and run it against a synthetic layer.

Complete worked example: we build a tiny plugin that scans a
:class:`DataLayer` for Windows TCP-endpoint pool-tag signatures
(``TcpE``), registers it with :func:`register_plugin`, registers it
into the context's :class:`PluginRegistry`, and runs it.

The decorator populates a module-global dict that
:class:`~deepview.plugins.registry.PluginRegistry` consults at
instantiation time. Tier 1 (built-ins) is discovered by importing
:mod:`deepview.plugins.builtin`, which triggers every
``@register_plugin`` decorator transitively. Our plugin uses the same
mechanism.

Usage:
    python examples/09_register_custom_plugin.py
    python examples/09_register_custom_plugin.py --count 12
"""
from __future__ import annotations

import argparse
import random
import struct

from deepview.core.context import AnalysisContext
from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin

from examples._synthetic import BytesLayer


# ---------------------------------------------------------------------------
# The plugin — decorated, registered at import time
# ---------------------------------------------------------------------------


@register_plugin(
    name="example_tcpe_scanner",
    category=PluginCategory.NETWORK_FORENSICS,
    description="Example plugin: scan for Windows TcpE pool tags",
    tags=["example", "network", "windows"],
)
class ExampleTcpEScanner(DeepViewPlugin):
    """Locate ``TcpE`` signatures inside a registered layer.

    This plugin consumes a layer by name (from
    :class:`~deepview.core.context.LayerRegistry`) and emits one row
    per hit. Requirements are declared via ``get_requirements`` so the
    CLI can validate inputs before running.
    """

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="layer",
                description="Name of a registered DataLayer to scan",
                required=True,
                default="target",
            ),
            Requirement(
                name="max_hits",
                description="Stop after this many matches",
                required=False,
                default=50,
            ),
        ]

    def run(self) -> PluginResult:
        layer_name = str(self.config.get("layer", "target"))
        max_hits = int(self.config.get("max_hits", 50))
        layer = self.context.layers.get(layer_name)

        read = getattr(layer, "read", None)
        max_addr = getattr(layer, "maximum_address", 0)
        if read is None:
            return PluginResult(
                columns=["error"], rows=[{"error": "layer has no read()"}])

        size = int(max_addr) + 1
        buf = read(0, size, pad=True)  # type: ignore[call-arg]
        needle = b"TcpE"
        rows: list[dict] = []
        start = 0
        while len(rows) < max_hits:
            idx = buf.find(needle, start)
            if idx < 0:
                break
            # Take the 16 bytes that typically follow a TcpE tag header
            # (in a real plugin this is the _TCP_ENDPOINT struct).
            context_bytes = buf[idx : idx + 16]
            rows.append({
                "offset": f"{idx:#x}",
                "context": context_bytes.hex(),
                "layer": layer_name,
            })
            start = idx + 4

        return PluginResult(
            columns=["offset", "context", "layer"],
            rows=rows,
            metadata={"scanned_bytes": size, "needle": "TcpE"},
        )


# ---------------------------------------------------------------------------
# Driver — build a synthetic layer with TcpE hits, run the plugin.
# ---------------------------------------------------------------------------


def build_synthetic_tcp_layer(num_hits: int = 8, size: int = 4096) -> BytesLayer:
    """Create a bytes layer with ``num_hits`` TcpE tags scattered inside it."""
    rng = random.Random(0x7E5715)
    buf = bytearray(rng.randbytes(size))
    stride = max(32, size // (num_hits + 1))
    for i in range(num_hits):
        off = (i + 1) * stride
        buf[off : off + 4] = b"TcpE"
        # A credible "endpoint" blob: local port, remote port, pid, state.
        blob = struct.pack(
            "<HHHHHHI",
            0x0050,  # local port 80 (BE vs LE ignored — this is synthetic)
            0xabcd,
            0xC0A8,  # 192.168
            0x0101,
            0x0050,
            0xabcd,
            1234,    # pid
        )
        buf[off + 4 : off + 4 + len(blob)] = blob
    return BytesLayer(bytes(buf), name="synthetic-tcp-mem")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--count", type=int, default=8,
                        help="number of synthetic TcpE hits to inject")
    parser.add_argument("--size", type=int, default=4096,
                        help="size of the synthetic layer in bytes")
    args = parser.parse_args()

    ctx = AnalysisContext.for_testing()
    layer = build_synthetic_tcp_layer(args.count, args.size)
    ctx.layers.register("target", layer)

    print(f"Registered synthetic layer: target (size={args.size} bytes, "
          f"expected hits={args.count})")

    # Verify the decorator populated the registry.
    from deepview.plugins.base import get_registered_plugins
    registered = get_registered_plugins()
    print(f"Registered plugin names (via decorator): "
          f"{sorted(k for k in registered if 'example' in k)}")

    # Instantiate and run.
    plugin = ExampleTcpEScanner(context=ctx, config={"layer": "target"})
    result = plugin.run()

    print()
    print(f"Columns: {result.columns}")
    print(f"Metadata: {result.metadata}")
    print(f"Rows ({len(result.rows)}):")
    for row in result.rows:
        print(f"  {row}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
