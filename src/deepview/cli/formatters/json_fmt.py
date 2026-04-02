"""JSON output formatter."""
from __future__ import annotations
import json
from typing import IO
from deepview.interfaces.plugin import PluginResult
from deepview.interfaces.renderer import ResultRenderer

class JSONRenderer(ResultRenderer):
    def format_name(self) -> str:
        return "json"

    def render(self, result: PluginResult, output: IO | None = None) -> str:
        data = {"columns": result.columns, "rows": result.rows, "metadata": result.metadata}
        text = json.dumps(data, indent=2, default=str)
        if output:
            output.write(text)
        return text
