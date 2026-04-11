"""Built-in persistence scan plugin."""
from __future__ import annotations

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


@register_plugin(
    name="persistence",
    category=PluginCategory.ROOTKIT_DETECTION,
    description="Enumerate persistence mechanisms across Linux, Windows, macOS, and containers",
    tags=["persistence", "mitre:T1543", "mitre:T1547", "mitre:T1053"],
)
class PersistencePlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="root",
                description="Root filesystem to scan (for offline images)",
                required=False,
                default="/",
            ),
            Requirement(
                name="manifest_roots",
                description="Directories containing K8s manifests to scan (comma-separated)",
                required=False,
                default="",
            ),
            Requirement(
                name="include_user_scope",
                description="Also scan user home directories",
                required=False,
                default=True,
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.detection.persistence.manager import PersistenceManager

        root = self.config.get("root") or "/"
        manifest_roots_raw = self.config.get("manifest_roots") or ""
        manifest_roots = [p for p in str(manifest_roots_raw).split(",") if p]
        include_user_scope = bool(self.config.get("include_user_scope", True))

        mgr = PersistenceManager(
            self.context,
            linux_root=root,
            macos_root=root,
            manifest_roots=manifest_roots or None,
        )
        findings = mgr.scan(include_user_scope=include_user_scope)
        rows = []
        for f in findings:
            rows.append(
                {
                    "mechanism": f.mechanism,
                    "location": f.location,
                    "mitre": f.mitre_technique,
                    "severity": f.severity.value,
                    "owner": f.owning_user,
                    "command": f.command[:200],
                    "reasons": ", ".join(f.suspicious_reasons),
                }
            )
        return PluginResult(
            columns=["mechanism", "location", "mitre", "severity", "owner", "command", "reasons"],
            rows=rows,
            metadata={
                "total": len(findings),
                "deviations": sum(1 for f in findings if f.deviation_from_baseline),
            },
        )
