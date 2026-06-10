"""STIX 2.1 and MITRE ATT&CK export."""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import TypedDict
from deepview.core.logging import get_logger
from deepview.detection.anti_forensics import Detection

log = get_logger("reporting.export")


class CoverageEntry(TypedDict):
    """One technique's deduped coverage across a set of detections."""

    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    count: int
    detections: list[str]


class STIXExporter:
    """Export findings as STIX 2.1 objects."""

    def export_detections(self, detections: list[Detection]) -> dict:
        """Convert detections to a STIX 2.1 bundle."""
        objects = []

        for detection in detections:
            # Create an Indicator for each detection
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": detection.name,
                "description": detection.description,
                "indicator_types": ["anomalous-activity"],
                "pattern": f"[process:pid = {detection.pid}]" if detection.pid else "[file:name = 'unknown']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
            }

            if detection.technique:
                indicator["external_references"] = [{
                    "source_name": "mitre-attack",
                    "external_id": detection.technique,
                    "url": f"https://attack.mitre.org/techniques/{detection.technique.replace('.', '/')}/",
                }]

            objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        return bundle

    def export_to_file(self, detections: list[Detection], output_path) -> None:
        """Export detections to a STIX 2.1 JSON file."""
        from pathlib import Path
        bundle = self.export_detections(detections)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bundle, indent=2))
        log.info("stix_exported", count=len(detections), output=str(path))


class ATTCKMapper:
    """Map detections to MITRE ATT&CK techniques."""

    # Mapping of detection names to ATT&CK techniques
    TECHNIQUE_MAP = {
        "DKOM_HIDDEN_PROCESS": {"id": "T1014", "name": "Rootkit", "tactic": "Defense Evasion"},
        "SSDT_HOOK": {"id": "T1574.013", "name": "KernelCallbackTable", "tactic": "Defense Evasion"},
        "INLINE_HOOK": {"id": "T1574", "name": "Hijack Execution Flow", "tactic": "Defense Evasion"},
        "PROCESS_HOLLOWING": {"id": "T1055.012", "name": "Process Hollowing", "tactic": "Defense Evasion"},
        "INJECTED_CODE": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        "SUSPICIOUS_THREAD": {"id": "T1055.003", "name": "Thread Execution Hijacking", "tactic": "Defense Evasion"},
        "PEB_MASQUERADE": {"id": "T1036.005", "name": "Match Legitimate Name", "tactic": "Defense Evasion"},
        "PATCHGUARD_BYPASS": {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
        "HYPERVISOR_ROOTKIT": {"id": "T1564.006", "name": "Run Virtual Instance", "tactic": "Defense Evasion"},
        "BOOTKIT": {"id": "T1542.003", "name": "Bootkit", "tactic": "Persistence"},
        "UNSIGNED_DRIVER": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        "DRIVER_INTEGRITY_MISMATCH": {"id": "T1014", "name": "Rootkit", "tactic": "Defense Evasion"},
    }

    # Friendly names for techniques that show up via ``attack_ids`` but are
    # not in the static detection-name map. Falls back to the id itself.
    TECHNIQUE_NAMES = {
        "T1003": "OS Credential Dumping",
        "T1055": "Process Injection",
        "T1059": "Command and Scripting Interpreter",
        "T1071": "Application Layer Protocol",
        "T1203": "Exploitation for Client Execution",
        "T1204": "User Execution",
        "T1486": "Data Encrypted for Impact",
        "T1489": "Service Stop",
        "T1547": "Boot or Logon Autostart Execution",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1562": "Impair Defenses",
        "T1574": "Hijack Execution Flow",
        "T1611": "Escape to Host",
    }

    _SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
    _SEVERITY_COLOR = {"critical": "#d64550", "warning": "#e8a13a", "info": "#f2d35c"}

    def map_detection(self, detection: Detection) -> dict[str, str] | None:
        """Map a single detection to an ATT&CK technique.

        Prefers the static detection-name map, then falls back to the
        detection's own ``technique`` id so any detector that fills in a
        MITRE id participates without needing a hardcoded entry.
        """
        mapping = self.TECHNIQUE_MAP.get(detection.name)
        if mapping is not None:
            return mapping
        technique = getattr(detection, "technique", "")
        if technique:
            base = technique.split(".")[0]
            return {
                "id": technique,
                "name": self.TECHNIQUE_NAMES.get(base, technique),
                "tactic": "unknown",
            }
        return None

    def map_all(self, detections: list[Detection]) -> list[dict]:
        """Map all detections and return technique coverage."""
        results = []
        for det in detections:
            technique = self.map_detection(det)
            if technique:
                results.append({
                    "detection": det.name,
                    "technique_id": technique["id"],
                    "technique_name": technique["name"],
                    "tactic": technique["tactic"],
                    "severity": det.severity.value,
                    "pid": det.pid,
                })
        return results

    def coverage(self, detections: list[Detection]) -> list[CoverageEntry]:
        """Per-technique coverage, deduped and rolled up to worst severity.

        This is the structured shape the HTML report's ATT&CK heatmap and
        the Navigator layer both build from.
        """
        by_id: dict[str, CoverageEntry] = {}
        for det in detections:
            mapping = self.map_detection(det)
            if mapping is None:
                continue
            tid = mapping["id"]
            sev = det.severity.value
            entry = by_id.get(tid)
            if entry is None:
                by_id[tid] = CoverageEntry(
                    technique_id=tid,
                    technique_name=mapping["name"],
                    tactic=mapping["tactic"],
                    severity=sev,
                    count=1,
                    detections=[det.name],
                )
            else:
                entry["count"] += 1
                if det.name not in entry["detections"]:
                    entry["detections"].append(det.name)
                if self._SEVERITY_RANK.get(sev, 0) > self._SEVERITY_RANK.get(
                    entry["severity"], 0
                ):
                    entry["severity"] = sev
        return sorted(by_id.values(), key=lambda e: e["technique_id"])

    def generate_navigator_layer(self, detections: list[Detection]) -> dict[str, object]:
        """Generate an ATT&CK Navigator layer JSON from dynamic coverage."""
        techniques = []
        for entry in self.coverage(detections):
            techniques.append({
                "techniqueID": entry["technique_id"],
                "color": self._SEVERITY_COLOR.get(entry["severity"], "#f2d35c"),
                "score": entry["count"],
                "comment": ", ".join(entry["detections"]),
                "enabled": True,
            })

        return {
            "name": "Deep View Forensic Analysis",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Techniques detected by Deep View forensic analysis",
            "techniques": techniques,
        }
