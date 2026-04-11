"""End-to-end test: DashboardApp + ManglePanel + NetworkPacketMangledEvent."""
from __future__ import annotations

import time

from deepview.cli.dashboard.app import DashboardApp
from deepview.cli.dashboard.config import load_dashboard_config
from deepview.cli.dashboard.panels import ManglePanel
from deepview.core.context import AnalysisContext
from deepview.core.events import NetworkPacketMangledEvent


class TestManglePanelIntegration:
    def test_mangle_panel_absorbs_core_bus_events(self):
        spec = load_dashboard_config(layout="mangle")
        app = DashboardApp(spec)
        mangle_panel = None
        for panel in app.panels:
            if isinstance(panel, ManglePanel):
                mangle_panel = panel
                break
        assert mangle_panel is not None

        ctx = AnalysisContext.for_testing()

        def _on_mangled(event: NetworkPacketMangledEvent) -> None:
            mangle_panel.ingest_mangle(
                action=event.action,
                rule_id=event.rule_id,
                remote=event.remote,
                ts_ns=event.ts_ns,
            )

        ctx.events.subscribe(NetworkPacketMangledEvent, _on_mangled)

        for rule_id, action in [
            ("r.drop_c2", "drop"),
            ("r.delay_exfil", "delayed"),
            ("r.drop_c2", "drop"),
            ("r.rewrite_dns", "rewritten"),
        ]:
            ctx.events.publish(
                NetworkPacketMangledEvent(
                    ts_ns=time.time_ns(),
                    rule_id=rule_id,
                    action=action,
                    verdict="drop" if action == "drop" else "modified",
                    direction="out",
                    remote="10.0.0.5:443/tcp",
                )
            )

        assert mangle_panel._counters["drop"] == 2
        assert mangle_panel._counters["delayed"] == 1
        assert mangle_panel._counters["rewritten"] == 1
        assert mangle_panel._by_rule["r.drop_c2"] == 2
        assert mangle_panel._by_rule["r.rewrite_dns"] == 1
        # Most recent shows first.
        assert mangle_panel._recent[0][2] == "r.rewrite_dns"
        # Panel renders without raising.
        from deepview.cli.dashboard.panels import FrameState

        out = mangle_panel.render(FrameState(now_ns=time.time_ns()))
        assert out is not None
