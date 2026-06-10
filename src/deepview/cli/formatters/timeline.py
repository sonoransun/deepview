"""Timeline output formatter.

Renders timestamped plugin results as a compact ASCII **swimlane** (one
lane per source/severity/category, density shown with block characters)
above the sorted detail table — a real temporal view rather than just a
timestamp-sorted table.
"""
from __future__ import annotations
from datetime import datetime
from typing import IO
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from deepview.interfaces.plugin import PluginResult
from deepview.interfaces.renderer import ResultRenderer

_BLOCKS = " ▁▂▃▄▅▆▇█"
_LANE_KEYS = ("severity", "source", "category")
_SWIMLANE_WIDTH = 48
_SEVERITY_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan"}


def _to_epoch(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return float(value)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return None
    return None


def _density_row(counts: list[int], vmax: int) -> str:
    vmax = vmax or 1
    out = []
    for c in counts:
        idx = min(len(_BLOCKS) - 1, int(c / vmax * (len(_BLOCKS) - 1)))
        out.append(_BLOCKS[idx])
    return "".join(out)


class TimelineRenderer(ResultRenderer):
    def format_name(self) -> str:
        return "timeline"

    def render(self, result: PluginResult, output: IO | None = None) -> str:
        console = Console(file=output) if output else Console()

        ts_col = None
        for col in result.columns:
            if "time" in col.lower() or "timestamp" in col.lower():
                ts_col = col
                break
        lane_col = next((c for c in result.columns if c.lower() in _LANE_KEYS), None)

        rows = result.rows
        if ts_col:
            rows = sorted(rows, key=lambda r: str(r.get(ts_col, "")))

        renderables: list[object] = []
        swimlane = self._swimlane(rows, ts_col, lane_col)
        if swimlane is not None:
            renderables.append(swimlane)

        table = Table(title="Timeline")
        for col in result.columns:
            style = "cyan" if col == ts_col else None
            table.add_column(col, style=style)
        for row in rows:
            table.add_row(*[str(row.get(col, "")) for col in result.columns])
        renderables.append(table)

        console.print(Group(*renderables))
        return ""

    def _swimlane(self, rows, ts_col, lane_col) -> Table | None:
        if not ts_col:
            return None
        stamped = [(_to_epoch(r.get(ts_col)), r) for r in rows]
        stamped = [(t, r) for t, r in stamped if t is not None]
        if len(stamped) < 2:
            return None
        t0 = min(t for t, _ in stamped)
        t1 = max(t for t, _ in stamped)
        span = (t1 - t0) or 1.0
        lanes: dict[str, list[int]] = {}
        for t, r in stamped:
            lane = str(r.get(lane_col, "all")) if lane_col else "all"
            bucket = min(_SWIMLANE_WIDTH - 1, int((t - t0) / span * (_SWIMLANE_WIDTH - 1)))
            counts = lanes.setdefault(lane, [0] * _SWIMLANE_WIDTH)
            counts[bucket] += 1
        vmax = max((max(c) for c in lanes.values()), default=1)
        grid = Table.grid(padding=(0, 1))
        grid.add_column(justify="right", min_width=10)
        grid.add_column()
        for lane in sorted(lanes):
            style = _SEVERITY_STYLE.get(lane, "white")
            grid.add_row(lane[:10], Text(_density_row(lanes[lane], vmax), style=style))
        return grid
