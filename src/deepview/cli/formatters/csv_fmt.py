"""CSV output formatter."""
from __future__ import annotations
import csv
import io
from typing import IO
from deepview.interfaces.plugin import PluginResult
from deepview.interfaces.renderer import ResultRenderer

class CSVRenderer(ResultRenderer):
    def format_name(self) -> str:
        return "csv"

    def render(self, result: PluginResult, output: IO | None = None) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=result.columns)
        writer.writeheader()
        for row in result.rows:
            writer.writerow({col: row.get(col, "") for col in result.columns})
        text = buf.getvalue()
        if output:
            output.write(text)
        return text
