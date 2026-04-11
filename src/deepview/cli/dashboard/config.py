"""Dashboard YAML config loader and built-in layouts.

A dashboard config is a small mapping with a ``layout`` section that
describes the region tree and a ``panels`` list that binds panel
types to regions. Built-in layouts ship under ``builtin_layouts/`` as
plain YAML files; :data:`BUILTIN_LAYOUTS` is the name → path index.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger

log = get_logger("cli.dashboard.config")


class DashboardConfigError(ValueError):
    """Raised when a dashboard config cannot be loaded or is invalid."""


@dataclass
class PanelSpec:
    name: str
    type: str
    region: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class LayoutSpec:
    """Parsed dashboard layout config.

    The ``layout`` dict maps region IDs to ``{direction, size, ratio}``
    descriptors that the layout builder feeds to ``rich.layout.Layout``.
    """

    refresh_hz: float
    layout: dict[str, Any]
    panels: list[PanelSpec]
    trace_probes: list[str]
    trace_filter: str | None
    classification_ruleset: str | None


_HERE = Path(__file__).parent
_BUILTIN_DIR = _HERE / "builtin_layouts"

BUILTIN_LAYOUTS: dict[str, Path] = {
    "network": _BUILTIN_DIR / "network.yaml",
    "full": _BUILTIN_DIR / "full.yaml",
    "minimal": _BUILTIN_DIR / "minimal.yaml",
    "mangle": _BUILTIN_DIR / "mangle.yaml",
}


def load_dashboard_config(
    *,
    layout: str | None = None,
    config_path: Path | None = None,
) -> LayoutSpec:
    """Resolve a dashboard config from either a built-in name or a file."""
    if config_path is not None:
        return load_layout_yaml(config_path)
    if layout is None:
        layout = "network"
    if layout not in BUILTIN_LAYOUTS:
        raise DashboardConfigError(
            f"unknown built-in layout {layout!r}; available: {sorted(BUILTIN_LAYOUTS)}"
        )
    return load_layout_yaml(BUILTIN_LAYOUTS[layout])


def load_layout_yaml(path: Path | str) -> LayoutSpec:
    """Parse one dashboard YAML file into a :class:`LayoutSpec`."""
    try:
        import yaml  # type: ignore
    except ImportError as e:
        raise DashboardConfigError(
            "PyYAML is required to load dashboard config files"
        ) from e

    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise DashboardConfigError(f"cannot read {p}: {e}") from e
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise DashboardConfigError(f"invalid YAML in {p}: {e}") from e
    if not isinstance(data, dict):
        raise DashboardConfigError(f"{p} must contain a YAML mapping at the top level")

    refresh_hz = float(data.get("refresh_hz", 4.0))
    layout_section = data.get("layout") or {}
    if not isinstance(layout_section, dict):
        raise DashboardConfigError(f"{p}: 'layout' must be a mapping")
    panels_section = data.get("panels") or []
    if not isinstance(panels_section, list):
        raise DashboardConfigError(f"{p}: 'panels' must be a list")

    panels: list[PanelSpec] = []
    for idx, entry in enumerate(panels_section):
        if not isinstance(entry, dict):
            raise DashboardConfigError(f"{p}: panels[{idx}] must be a mapping")
        ptype = entry.get("type")
        if not ptype:
            raise DashboardConfigError(f"{p}: panels[{idx}] is missing 'type'")
        region = entry.get("region") or ptype
        name = entry.get("name") or ptype
        config = {
            k: v for k, v in entry.items() if k not in ("type", "region", "name")
        }
        panels.append(
            PanelSpec(name=str(name), type=str(ptype), region=str(region), config=config)
        )

    trace = data.get("trace") or {}
    if not isinstance(trace, dict):
        raise DashboardConfigError(f"{p}: 'trace' must be a mapping")
    probes = trace.get("probes") or ["process"]
    if not isinstance(probes, list):
        raise DashboardConfigError(f"{p}: 'trace.probes' must be a list")
    trace_filter = trace.get("filter")

    classification = data.get("classification") or {}
    if not isinstance(classification, dict):
        raise DashboardConfigError(f"{p}: 'classification' must be a mapping")
    ruleset = classification.get("ruleset")

    return LayoutSpec(
        refresh_hz=refresh_hz,
        layout=dict(layout_section),
        panels=panels,
        trace_probes=[str(p) for p in probes],
        trace_filter=str(trace_filter) if trace_filter else None,
        classification_ruleset=str(ruleset) if ruleset else None,
    )
