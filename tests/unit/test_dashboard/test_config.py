"""Tests for the dashboard YAML config loader."""
from __future__ import annotations

import textwrap

import pytest

from deepview.cli.dashboard.config import (
    BUILTIN_LAYOUTS,
    DashboardConfigError,
    load_dashboard_config,
    load_layout_yaml,
)


class TestBuiltinLayouts:
    @pytest.mark.parametrize("name", list(BUILTIN_LAYOUTS.keys()))
    def test_each_builtin_loads(self, name):
        spec = load_dashboard_config(layout=name)
        assert spec.refresh_hz > 0
        assert len(spec.panels) >= 1
        # Every region referenced by a panel must be unique-ish or repeat intentionally.
        for panel in spec.panels:
            assert panel.type
            assert panel.region

    def test_unknown_layout_raises(self):
        with pytest.raises(DashboardConfigError, match="unknown"):
            load_dashboard_config(layout="does-not-exist")


class TestCustomYaml:
    def test_minimal_custom_layout(self, tmp_path):
        path = tmp_path / "custom.yaml"
        path.write_text(
            textwrap.dedent(
                """
                refresh_hz: 2
                trace:
                  probes: [process]
                layout:
                  root:
                    direction: vertical
                    children:
                      - {id: top, size: 3}
                      - {id: body, ratio: 1}
                panels:
                  - name: h
                    type: header
                    region: top
                  - name: tail
                    type: event_tail
                    region: body
                    max_rows: 5
                """
            )
        )
        spec = load_layout_yaml(path)
        assert spec.refresh_hz == 2
        assert [p.type for p in spec.panels] == ["header", "event_tail"]
        assert spec.panels[1].config == {"max_rows": 5}

    def test_missing_panel_type_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text(
            textwrap.dedent(
                """
                panels:
                  - name: h
                    region: top
                """
            )
        )
        with pytest.raises(DashboardConfigError, match="type"):
            load_layout_yaml(path)

    def test_top_level_must_be_mapping(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("- just-a-list\n")
        with pytest.raises(DashboardConfigError, match="mapping"):
            load_layout_yaml(path)
