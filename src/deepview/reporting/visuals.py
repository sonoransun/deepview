"""Self-contained inline-SVG visuals for HTML reports.

Structural visuals (timeline swimlane, ATT&CK coverage matrix, process
tree) are hand-built SVG so they are deterministic and unit-testable and
embed inline with no external assets. Statistical charts (severity
distribution, event rate) use matplotlib's headless ``Agg`` backend
rendered to inline SVG; matplotlib is imported lazily so importing this
module stays cheap, and a missing/broken backend degrades to a small
placeholder rather than raising.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Sequence

if TYPE_CHECKING:
    from deepview.analysis.process_tree import ProcessTree
    from deepview.reporting.export import CoverageEntry
    from deepview.reporting.timeline import TimelineEntry

SEVERITY_COLORS = {
    "critical": "#d64550",
    "warning": "#e8a13a",
    "info": "#3b82c4",
}
_SEVERITY_FALLBACK = "#6b7280"


def _color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, _SEVERITY_FALLBACK)


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _placeholder(label: str, *, width: int = 480, height: int = 40) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'role="img"><text x="8" y="24" font-family="monospace" font-size="12" '
        f'fill="#888">{_xml_escape(label)}</text></svg>'
    )


# ---------------------------------------------------------------------------
# Hand-built structural SVG
# ---------------------------------------------------------------------------


def timeline_svg(
    lanes: dict[str, list[TimelineEntry]],
    *,
    width: int = 900,
    lane_h: int = 34,
    margin: int = 12,
    label_w: int = 130,
) -> str:
    """Render lanes of timeline entries as an SVG swimlane.

    Each lane is a horizontal track; entries are dots positioned by time
    and colored by severity. A single-instant span collapses to the left.
    """
    all_entries = [e for entries in lanes.values() for e in entries]
    if not all_entries:
        return _placeholder("(no timeline entries)", width=width)
    times = [e.timestamp for e in all_entries]
    t0, t1 = min(times), max(times)
    span = (t1 - t0).total_seconds() or 1.0
    track_w = width - label_w - margin * 2
    height = margin * 2 + len(lanes) * lane_h
    parts: list[str] = []
    for row, (lane_name, entries) in enumerate(sorted(lanes.items())):
        y = margin + row * lane_h
        cy = y + lane_h // 2
        parts.append(
            f'<text x="{margin}" y="{cy + 4}" font-family="monospace" '
            f'font-size="12" fill="#333">{_xml_escape(lane_name[:16])}</text>'
        )
        parts.append(
            f'<line x1="{label_w}" y1="{cy}" x2="{label_w + track_w}" y2="{cy}" '
            f'stroke="#e0e0e0" stroke-width="1"/>'
        )
        for entry in entries:
            frac = (entry.timestamp - t0).total_seconds() / span
            cx = label_w + int(frac * track_w)
            title = _xml_escape(f"{entry.timestamp.isoformat()} {entry.description}")
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="5" fill="{_color(entry.severity)}">'
                f"<title>{title}</title></circle>"
            )
    body = "".join(parts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'role="img" aria-label="event timeline">{body}</svg>'
    )


def attack_matrix_svg(
    coverage: Sequence[CoverageEntry],
    *,
    width: int = 900,
    cols: int = 6,
    cell_w: int = 140,
    cell_h: int = 46,
    margin: int = 12,
    gap: int = 8,
) -> str:
    """Render ATT&CK technique coverage as a colored cell grid."""
    if not coverage:
        return _placeholder("(no ATT&CK techniques detected)", width=width)
    rows = (len(coverage) + cols - 1) // cols
    height = margin * 2 + rows * (cell_h + gap)
    parts: list[str] = []
    for i, entry in enumerate(coverage):
        col = i % cols
        row = i // cols
        x = margin + col * (cell_w + gap)
        y = margin + row * (cell_h + gap)
        fill = _color(str(entry["severity"]))
        tid = _xml_escape(str(entry["technique_id"]))
        name = _xml_escape(str(entry["technique_name"])[:18])
        count = entry["count"]
        parts.append(
            f'<rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" rx="5" '
            f'fill="{fill}" fill-opacity="0.85" stroke="#333" stroke-width="0.5"/>'
            f'<text x="{x + 8}" y="{y + 18}" font-family="monospace" font-size="12" '
            f'font-weight="bold" fill="#fff">{tid} ({count})</text>'
            f'<text x="{x + 8}" y="{y + 34}" font-family="monospace" font-size="10" '
            f'fill="#fff">{name}</text>'
        )
    body = "".join(parts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'role="img" aria-label="ATT&amp;CK coverage">{body}</svg>'
    )


def process_tree_svg(tree: ProcessTree, *, width: int = 900) -> str:
    """Render a :class:`ProcessTree` to SVG (delegates to the model)."""
    return tree.to_svg(width=width)


# ---------------------------------------------------------------------------
# matplotlib statistical charts (lazy, headless, fail-soft)
# ---------------------------------------------------------------------------


def _mpl_svg(render: Callable[[Any], None]) -> str:
    """Run ``render(ax)`` on a headless figure and return inline SVG."""
    import io

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001 - matplotlib optional/broken backend
        return ""
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    try:
        render(ax)
        buf = io.StringIO()
        fig.savefig(buf, format="svg", bbox_inches="tight")
    finally:
        plt.close(fig)
    svg = buf.getvalue()
    idx = svg.find("<svg")
    return svg[idx:] if idx != -1 else ""


def severity_chart_svg(counts: dict[str, int]) -> str:
    """Bar chart of finding counts by severity."""
    ordered = [(s, counts.get(s, 0)) for s in ("critical", "warning", "info") if counts.get(s)]
    if not ordered:
        return _placeholder("(no findings)")

    def render(ax: Any) -> None:
        labels = [s for s, _ in ordered]
        values = [v for _, v in ordered]
        ax.bar(labels, values, color=[_color(s) for s in labels])
        ax.set_title("Findings by severity")
        ax.set_ylabel("count")

    svg = _mpl_svg(render)
    return svg or _placeholder("(severity chart unavailable)")


def rate_chart_svg(series: Sequence[int]) -> str:
    """Line chart of an event-rate series."""
    if not series:
        return _placeholder("(no rate data)")

    def render(ax: Any) -> None:
        ax.plot(list(range(len(series))), list(series), color="#3b82c4")
        ax.fill_between(list(range(len(series))), list(series), color="#3b82c4", alpha=0.2)
        ax.set_title("Event rate")
        ax.set_xlabel("bucket")
        ax.set_ylabel("events")

    svg = _mpl_svg(render)
    return svg or _placeholder("(rate chart unavailable)")
