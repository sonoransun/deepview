"""Tests for the inline-SVG report visuals."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from deepview.analysis.process_tree import ProcessTree
from deepview.reporting import visuals
from deepview.reporting.timeline import TimelineEntry


def _entries():
    base = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
    return {
        "critical": [
            TimelineEntry(base, "x", "boom", "trace", "critical"),
            TimelineEntry(base + timedelta(seconds=5), "x", "boom2", "trace", "critical"),
        ],
        "info": [TimelineEntry(base + timedelta(seconds=2), "x", "ok", "trace", "info")],
    }


class TestTimelineSvg:
    def test_wellformed_with_lanes(self):
        svg = visuals.timeline_svg(_entries())
        assert svg.startswith("<svg")
        assert svg.rstrip().endswith("</svg>")
        # three entries -> three circles.
        assert svg.count("<circle") == 3

    def test_empty(self):
        svg = visuals.timeline_svg({})
        assert svg.startswith("<svg")
        assert "no timeline" in svg


class TestAttackMatrixSvg:
    def test_renders_cells(self):
        coverage = [
            {"technique_id": "T1055", "technique_name": "Injection", "tactic": "x",
             "severity": "critical", "count": 2, "detections": ["a"]},
            {"technique_id": "T1014", "technique_name": "Rootkit", "tactic": "x",
             "severity": "warning", "count": 1, "detections": ["b"]},
        ]
        svg = visuals.attack_matrix_svg(coverage)
        assert svg.startswith("<svg")
        assert svg.count("<rect") == 2
        assert "T1055" in svg

    def test_empty(self):
        assert "techniques detected" in visuals.attack_matrix_svg([])


class TestProcessTreeSvg:
    def test_delegates_to_tree(self):
        tree = ProcessTree()
        tree.add(1, 0, "init")
        tree.add(2, 1, "bash")
        svg = visuals.process_tree_svg(tree)
        assert svg.startswith("<svg")
        assert svg.count("<rect") == 2


class TestCharts:
    def test_severity_chart_is_svg_or_placeholder(self):
        svg = visuals.severity_chart_svg({"critical": 2, "warning": 1, "info": 0})
        assert svg.startswith("<svg")

    def test_severity_chart_empty(self):
        assert "no findings" in visuals.severity_chart_svg({"critical": 0})

    def test_rate_chart(self):
        svg = visuals.rate_chart_svg([1, 3, 2, 5])
        assert svg.startswith("<svg")
