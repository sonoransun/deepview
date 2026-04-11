"""Rich Layout builder driven by a :class:`LayoutSpec`.

The layout section of a dashboard YAML describes a region tree like::

    layout:
      root:
        direction: vertical
        children:
          - {id: top, size: 3}
          - id: middle
            direction: horizontal
            children:
              - {id: middle-left, ratio: 1}
              - {id: middle-right, ratio: 1}
          - {id: bottom, ratio: 2}

:class:`DashboardLayout` walks that tree once to build a
``rich.layout.Layout`` and then lets the app attach panel renderables
to leaf regions by ID.
"""
from __future__ import annotations

from typing import Any

from rich.layout import Layout
from rich.panel import Panel as RichPanel
from rich.text import Text

from deepview.cli.dashboard.config import LayoutSpec
from deepview.cli.dashboard.panels import FrameState, Panel


class DashboardLayout:
    """Bridge between a :class:`LayoutSpec` and ``rich.layout.Layout``."""

    def __init__(self, spec: LayoutSpec, panels: list[Panel]) -> None:
        self._spec = spec
        self._panels = panels
        self._root = Layout(name="root")
        self._leaf_ids: set[str] = set()
        self._build(self._root, spec.layout.get("root") or _default_tree(spec))
        self._panels_by_region: dict[str, list[Panel]] = {}
        for panel_spec, panel in zip(spec.panels, panels, strict=True):
            self._panels_by_region.setdefault(panel_spec.region, []).append(panel)

    @property
    def root(self) -> Layout:
        return self._root

    def render(self, frame: FrameState) -> Layout:
        """Ask every panel for its current renderable and attach it."""
        for region, panels in self._panels_by_region.items():
            if region not in self._leaf_ids:
                continue
            if len(panels) == 1:
                try:
                    self._root[region].update(panels[0].render(frame))
                except Exception as e:  # noqa: BLE001
                    self._root[region].update(
                        RichPanel(Text(f"panel error: {e}", style="red"))
                    )
            else:
                # Stack multiple panels vertically into one region.
                from rich.console import Group

                renderables = []
                for p in panels:
                    try:
                        renderables.append(p.render(frame))
                    except Exception as e:  # noqa: BLE001
                        renderables.append(
                            RichPanel(Text(f"panel error: {e}", style="red"))
                        )
                self._root[region].update(Group(*renderables))
        return self._root

    # ------------------------------------------------------------------
    # Builder
    # ------------------------------------------------------------------

    def _build(self, parent: Layout, node: dict[str, Any]) -> None:
        direction = node.get("direction", "vertical")
        children = node.get("children") or []
        split_args: list[Layout] = []
        for child in children:
            name = child.get("id") or child.get("name") or "_"
            sub = Layout(name=name)
            if "size" in child:
                sub.size = int(child["size"])
            if "ratio" in child:
                sub.ratio = int(child["ratio"])
            if child.get("children"):
                self._build(sub, child)
            else:
                self._leaf_ids.add(name)
            split_args.append(sub)
        if not split_args:
            self._leaf_ids.add(parent.name)
            return
        if direction == "horizontal":
            parent.split_row(*split_args)
        else:
            parent.split_column(*split_args)


def _default_tree(spec: LayoutSpec) -> dict[str, Any]:
    """Fallback region tree when ``layout.root`` is not supplied.

    Builds a single-column stack of every panel's region in order.
    """
    regions = list(dict.fromkeys(p.region for p in spec.panels))
    return {
        "direction": "vertical",
        "children": [{"id": r, "ratio": 1} for r in regions],
    }
