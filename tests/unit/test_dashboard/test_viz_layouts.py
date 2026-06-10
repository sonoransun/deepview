"""The viz built-in layouts build a full DashboardApp."""
from __future__ import annotations

import pytest

from deepview.cli.dashboard.app import DashboardApp
from deepview.cli.dashboard.config import load_dashboard_config


@pytest.mark.parametrize("layout", ["triage", "memory"])
def test_layout_instantiates_every_panel(layout):
    spec = load_dashboard_config(layout=layout)
    app = DashboardApp(spec)
    # Every panel spec resolved to a concrete panel instance.
    assert len(app.panels) == len(spec.panels)
    # And the layout renders a frame without raising.
    assert app.render_frame() is not None
