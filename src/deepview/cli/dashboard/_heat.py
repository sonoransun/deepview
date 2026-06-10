"""Truecolor intensity ramp helpers for heatmap-style panels.

The original panels used an 8-color ANSI palette; the heat panels want a
smooth cool-to-hot gradient so a forensic analyst can read intensity at a
glance. These helpers emit ``#rrggbb`` truecolor hex (understood by Rich)
and build a row of block characters shaded by per-cell intensity.
"""
from __future__ import annotations

from rich.text import Text

# Cool -> hot ramp stops (low activity is calm blue, spikes are red).
_RAMP: tuple[tuple[int, int, int], ...] = (
    (27, 31, 58),
    (39, 64, 139),
    (30, 136, 168),
    (59, 178, 115),
    (200, 192, 32),
    (232, 144, 42),
    (214, 69, 80),
)
_BLOCKS = " ▁▂▃▄▅▆▇█"


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def heat_hex(norm: float) -> str:
    """Map a normalised 0..1 intensity to an interpolated ramp hex color."""
    norm = _clamp(norm)
    if norm <= 0:
        r, g, b = _RAMP[0]
        return f"#{r:02x}{g:02x}{b:02x}"
    pos = norm * (len(_RAMP) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(_RAMP) - 1)
    frac = pos - lo
    r0, g0, b0 = _RAMP[lo]
    r1, g1, b1 = _RAMP[hi]
    r = round(r0 + (r1 - r0) * frac)
    g = round(g0 + (g1 - g0) * frac)
    b = round(b0 + (b1 - b0) * frac)
    return f"#{r:02x}{g:02x}{b:02x}"


def _block(norm: float) -> str:
    norm = _clamp(norm)
    return _BLOCKS[min(len(_BLOCKS) - 1, int(norm * (len(_BLOCKS) - 1)))]


def heat_row(values: list[int], vmax: int | None = None) -> Text:
    """Render a sequence of counts as colored intensity blocks."""
    text = Text()
    if not values:
        return Text("·", style="dim")
    top = vmax if vmax is not None else max(values)
    top = top or 1
    for v in values:
        norm = _clamp(v / top)
        text.append(_block(norm), style=heat_hex(norm))
    return text
