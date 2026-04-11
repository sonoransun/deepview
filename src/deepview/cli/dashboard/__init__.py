"""Multi-panel configurable Rich dashboard.

This package generalises the single-table :class:`LiveRenderer` in
``cli/formatters/live.py`` into a real multi-panel dashboard driven
by a YAML layout config. Panels subscribe to the existing
``TraceEventBus`` / ``EventBus`` and render independently; the
dashboard app drives refresh at a configurable rate.
"""
from __future__ import annotations

from deepview.cli.dashboard.app import DashboardApp
from deepview.cli.dashboard.config import (
    BUILTIN_LAYOUTS,
    DashboardConfigError,
    load_dashboard_config,
    load_layout_yaml,
)
from deepview.cli.dashboard.layout import DashboardLayout
from deepview.cli.dashboard.panels import Panel, PanelRegistry, default_panel_registry

__all__ = [
    "DashboardApp",
    "DashboardLayout",
    "BUILTIN_LAYOUTS",
    "DashboardConfigError",
    "Panel",
    "PanelRegistry",
    "default_panel_registry",
    "load_dashboard_config",
    "load_layout_yaml",
]
