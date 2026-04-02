"""Timeline output formatter."""
from __future__ import annotations
from typing import IO
from rich.console import Console
from rich.table import Table
from deepview.interfaces.plugin import PluginResult
from deepview.interfaces.renderer import ResultRenderer

class TimelineRenderer(ResultRenderer):
    def format_name(self) -> str:
        return "timeline"

    def render(self, result: PluginResult, output: IO | None = None) -> str:
        console = Console(file=output) if output else Console()
        table = Table(title="Timeline")
        # Try to identify timestamp column
        ts_col = None
        for col in result.columns:
            if "time" in col.lower() or "timestamp" in col.lower():
                ts_col = col
                break

        for col in result.columns:
            style = "cyan" if col == ts_col else None
            table.add_column(col, style=style)

        # Sort by timestamp if available
        rows = result.rows
        if ts_col:
            rows = sorted(rows, key=lambda r: r.get(ts_col, ""))

        for row in rows:
            table.add_row(*[str(row.get(col, "")) for col in result.columns])
        console.print(table)
        return ""
