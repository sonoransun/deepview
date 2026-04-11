"""On-demand live inspection primitives.

These modules answer questions like "what does pid 1234 look like
*right now*" without spinning up the full trace/replay pipeline.
They share a :class:`deepview.interfaces.plugin.PluginResult` output
shape so the existing table/JSON/CSV formatters render them for free.
"""
from __future__ import annotations

from deepview.inspect.file import FileInspector
from deepview.inspect.live_layer import LiveProcessLayer
from deepview.inspect.memory_peek import MemoryPeek
from deepview.inspect.net import NetInspector
from deepview.inspect.process import ProcessInspector

__all__ = [
    "ProcessInspector",
    "LiveProcessLayer",
    "MemoryPeek",
    "FileInspector",
    "NetInspector",
]
