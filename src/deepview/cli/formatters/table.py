"""Rich table output formatter."""
from __future__ import annotations
from typing import IO
from rich.console import Console
from rich.table import Table
from deepview.interfaces.plugin import PluginResult
from deepview.interfaces.renderer import ResultRenderer

class TableRenderer(ResultRenderer):
    """Render plugin results as Rich tables."""

    def format_name(self) -> str:
        return "table"

    def render(self, result: PluginResult, output: IO | None = None) -> str:
        console = Console(file=output) if output else Console()
        table = Table()
        for col in result.columns:
            table.add_column(col)
        for row in result.rows:
            table.add_row(*[str(row.get(col, "")) for col in result.columns])
        console.print(table)
        return ""
