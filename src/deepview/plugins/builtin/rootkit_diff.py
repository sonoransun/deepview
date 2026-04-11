"""Differential rootkit hunt plugin.

Finally gives ``PluginCategory.DIFFERENTIAL`` an implementation: takes a
stored baseline snapshot, captures the current host state, diffs them,
runs the baseline rule set, and returns a table of findings.
"""
from __future__ import annotations

from pathlib import Path

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="rootkit_diff",
    category=PluginCategory.DIFFERENTIAL,
    description="Diff current host state against a stored baseline snapshot and flag rootkit-class deviations",
    tags=["differential", "baseline", "rootkit", "mitre:T1014"],
)
class RootkitDiffPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="store",
                description="Path to the snapshot SQLite store",
                required=False,
                default="",
            ),
            Requirement(
                name="host_id",
                description="Host id to diff (defaults to current host)",
                required=False,
                default="",
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.baseline import (
            DEFAULT_BASELINE_RULES,
            DeviationPublisher,
            HostSnapshot,
            SnapshotDiffer,
            SnapshotStore,
        )
        from deepview.baseline.rules import run_rules

        store_path_raw = self.config.get("store") or ""
        store_path = Path(store_path_raw) if store_path_raw else (
            Path(self.context.config.cache_dir) / "snapshots.db"
        )
        if not store_path.exists():
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"No snapshot store at {store_path}"}],
            )
        store = SnapshotStore(store_path)
        host_id = self.config.get("host_id") or None
        import platform as _platform

        if not host_id:
            host_id = _platform.node() or "localhost"
        baseline = store.latest(host_id)
        if baseline is None:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"No baseline for host {host_id}"}],
            )
        current = HostSnapshot.capture_current(host_id=host_id)
        delta = SnapshotDiffer().diff(baseline, current)
        publisher = DeviationPublisher(self.context.events)
        event_count = publisher.publish(delta)
        findings = run_rules(delta, DEFAULT_BASELINE_RULES)
        rows = []
        for f in findings:
            rows.append(
                {
                    "rule": f.rule_id,
                    "severity": f.severity.value,
                    "mitre": ",".join(f.mitre_techniques),
                    "description": f.description,
                }
            )
        return PluginResult(
            columns=["rule", "severity", "mitre", "description"],
            rows=rows,
            metadata={
                "events_published": event_count,
                "baseline_snapshot": baseline.snapshot_id,
                "current_snapshot": current.snapshot_id,
            },
        )
