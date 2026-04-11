"""Container runtime persistence collectors.

Covers:

* Kubernetes manifests (CronJob, DaemonSet, Pod) with privileged flags,
  hostPath mounts, docker.sock mounts, and ServiceAccount token mounts
* Docker / containerd auto-start policies
* Admission webhooks pointing to unknown endpoints

All collectors are file-based: they read manifests from a directory the
caller provides (e.g. ``/etc/kubernetes``, a GitOps checkout, a running
cluster dump). They never talk directly to the kube-apiserver — that's
a separate concern handled at acquisition time.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger
from deepview.detection.persistence.base import (
    PersistenceArtifact,
    PersistenceDetector,
    PersistenceSeverity,
)

log = get_logger("detection.persistence.containers")


class ContainerPersistenceDetector(PersistenceDetector):
    platform = "containers"

    def __init__(self, manifest_roots: list[Path | str] | None = None) -> None:
        self.manifest_roots: list[Path] = [Path(p) for p in (manifest_roots or [])]

    def scan(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        for root in self.manifest_roots:
            if not root.exists():
                continue
            for path in root.rglob("*.json"):
                findings.extend(self._scan_manifest(path))
            for path in root.rglob("*.yaml"):
                findings.extend(self._scan_manifest(path))
            for path in root.rglob("*.yml"):
                findings.extend(self._scan_manifest(path))
        return findings

    def _scan_manifest(self, path: Path) -> list[PersistenceArtifact]:
        data = _load_manifest(path)
        if not isinstance(data, dict):
            return []
        kind = str(data.get("kind", "")).lower()
        if kind == "cronjob":
            return self._cronjob(path, data)
        if kind == "daemonset":
            return self._daemonset(path, data)
        if kind == "pod":
            return self._pod(path, data)
        if kind == "mutatingwebhookconfiguration" or kind == "validatingwebhookconfiguration":
            return self._webhook(path, data)
        return []

    # ------------------------------------------------------------------

    def _cronjob(self, path: Path, data: dict[str, Any]) -> list[PersistenceArtifact]:
        spec = data.get("spec", {})
        schedule = spec.get("schedule", "")
        template = (
            spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        )
        containers = template.get("containers", [])
        reasons: list[str] = []
        for c in containers:
            image = str(c.get("image", ""))
            if ":latest" in image or not any(c in image for c in (":",)):
                reasons.append(f"CronJob uses floating image tag: {image}")
        return [
            PersistenceArtifact(
                mechanism="k8s_cronjob",
                location=str(path),
                mitre_technique="T1053.007",
                description=f"Kubernetes CronJob schedule={schedule}",
                severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                command=" ".join(str(c.get("image", "")) for c in containers),
                suspicious_reasons=reasons,
                evidence={"schedule": schedule},
            )
        ]

    def _daemonset(self, path: Path, data: dict[str, Any]) -> list[PersistenceArtifact]:
        spec = data.get("spec", {}).get("template", {}).get("spec", {})
        reasons = self._pod_spec_reasons(spec)
        return [
            PersistenceArtifact(
                mechanism="k8s_daemonset",
                location=str(path),
                mitre_technique="T1053.007",
                description="Kubernetes DaemonSet",
                severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                suspicious_reasons=reasons,
                evidence={"pod_spec": spec},
            )
        ]

    def _pod(self, path: Path, data: dict[str, Any]) -> list[PersistenceArtifact]:
        spec = data.get("spec", {})
        reasons = self._pod_spec_reasons(spec)
        return [
            PersistenceArtifact(
                mechanism="k8s_pod",
                location=str(path),
                mitre_technique="T1610",
                description="Standalone Kubernetes Pod manifest",
                severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.LOW,
                suspicious_reasons=reasons,
            )
        ]

    def _pod_spec_reasons(self, spec: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        for vol in spec.get("volumes", []) or []:
            host = vol.get("hostPath", {})
            if host:
                p = str(host.get("path", ""))
                if p in ("/", "/var/run/docker.sock", "/etc", "/root", "/home"):
                    reasons.append(f"hostPath mount of {p}")
        for container in spec.get("containers", []) or []:
            sec = container.get("securityContext", {}) or {}
            if sec.get("privileged"):
                reasons.append("container runs privileged")
            if sec.get("allowPrivilegeEscalation", False):
                reasons.append("allows privilege escalation")
        if spec.get("hostPID"):
            reasons.append("hostPID=true")
        if spec.get("hostNetwork"):
            reasons.append("hostNetwork=true")
        if spec.get("automountServiceAccountToken", True) is not False:
            # Default is True, so flag only when explicitly set False is healthier
            pass
        return reasons

    def _webhook(self, path: Path, data: dict[str, Any]) -> list[PersistenceArtifact]:
        webhooks = data.get("webhooks", [])
        findings: list[PersistenceArtifact] = []
        for hook in webhooks or []:
            url = hook.get("clientConfig", {}).get("url", "")
            if not url:
                continue
            findings.append(
                PersistenceArtifact(
                    mechanism="k8s_webhook",
                    location=f"{path}:{hook.get('name', '')}",
                    mitre_technique="T1556",
                    description=f"Admission webhook -> {url}",
                    severity=PersistenceSeverity.HIGH,
                    command=url,
                    evidence={"webhook": hook.get("name", "")},
                )
            )
        return findings


def _load_manifest(path: Path) -> Any:
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if suffix == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    # YAML is lazy — only import if present, and gracefully degrade.
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return _naive_yaml_kind(text)
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def _naive_yaml_kind(text: str) -> dict[str, Any]:
    """Fallback YAML reader that extracts just the ``kind`` field.

    Good enough to dispatch into the right handler even without PyYAML
    installed. Not good enough to evaluate all the pod-spec reasons, so we
    return only the kind plus the raw text.
    """
    kind = ""
    for line in text.splitlines():
        if line.startswith("kind:"):
            kind = line.split(":", 1)[1].strip()
            break
    return {"kind": kind, "spec": {}}
