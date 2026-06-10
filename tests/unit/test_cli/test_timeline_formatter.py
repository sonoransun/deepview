"""Tests for the visual timeline output formatter."""
from __future__ import annotations

import io

from deepview.cli.formatters.timeline import TimelineRenderer
from deepview.interfaces.plugin import PluginResult


def _result() -> PluginResult:
    return PluginResult(
        columns=["timestamp", "severity", "description"],
        rows=[
            {"timestamp": "2026-06-09T12:00:00", "severity": "critical", "description": "a"},
            {"timestamp": "2026-06-09T12:00:05", "severity": "info", "description": "b"},
            {"timestamp": "2026-06-09T12:00:10", "severity": "critical", "description": "c"},
        ],
    )


class TestTimelineRenderer:
    def test_renders_swimlane_and_table(self):
        buf = io.StringIO()
        TimelineRenderer().render(_result(), output=buf)
        out = buf.getvalue()
        # Detail table title present.
        assert "Timeline" in out
        # Lane labels for the two severities present in the swimlane.
        assert "critical" in out
        assert "info" in out

    def test_single_timestamp_skips_swimlane(self):
        result = PluginResult(
            columns=["timestamp", "description"],
            rows=[{"timestamp": "2026-06-09T12:00:00", "description": "only"}],
        )
        buf = io.StringIO()
        TimelineRenderer().render(result, output=buf)
        assert "Timeline" in buf.getvalue()
