"""Timeline plugin — delegates to :class:`TimelineMerger`.

Replaces the old artifact-store sorter. This plugin enables any of the
registered :mod:`deepview.reporting.timeline.sources` via options.
"""
from __future__ import annotations

from pathlib import Path

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="timeliner",
    category=PluginCategory.TIMELINE,
    description="Merged forensic timeline with cross-source correlation and timestomping detection",
    tags=["timeline", "timestamps", "mitre:T1070.006"],
)
class TimelinerPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="filesystem_paths",
                description="Comma-separated list of file paths to MACB-harvest",
                required=False,
                default="",
            ),
            Requirement(
                name="auditd_log",
                description="Path to /var/log/audit/audit.log",
                required=False,
                default="",
            ),
            Requirement(
                name="include_journald",
                description="Include journald output",
                required=False,
                default=False,
            ),
            Requirement(
                name="include_memory_artifacts",
                description="Include artifacts from the context's artifact store",
                required=False,
                default=True,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.reporting.timeline.merger import TimelineMerger
        from deepview.reporting.timeline.sources import (
            AuditdSource,
            FilesystemSource,
            JournaldSource,
            MemoryArtifactSource,
        )

        merger = TimelineMerger()
        fs_paths_raw = self.config.get("filesystem_paths") or ""
        fs_paths = [Path(p) for p in str(fs_paths_raw).split(",") if p]
        if fs_paths:
            merger.add_source(FilesystemSource(fs_paths))

        auditd_log = self.config.get("auditd_log") or ""
        if auditd_log:
            merger.add_source(AuditdSource([Path(auditd_log)]))

        if self.config.get("include_journald"):
            merger.add_source(JournaldSource())

        if self.config.get("include_memory_artifacts", True):
            merger.add_source(
                MemoryArtifactSource(self.context.artifacts.all_artifacts())
            )

        events = merger.build()
        rows = [
            {
                "timestamp": e.timestamp_utc.isoformat(),
                "source": e.source.value,
                "severity": e.severity.value,
                "description": e.description[:200],
                "mitre": ",".join(e.mitre_techniques),
            }
            for e in events
        ]
        return PluginResult(
            columns=["timestamp", "source", "severity", "description", "mitre"],
            rows=rows,
            metadata={"total": len(events)},
        )
