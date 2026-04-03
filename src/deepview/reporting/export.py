"""STIX 2.1 and MITRE ATT&CK export."""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from deepview.core.logging import get_logger
from deepview.detection.anti_forensics import Detection

log = get_logger("reporting.export")


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

    def map_detection(self, detection: Detection) -> dict | None:
        """Map a single detection to ATT&CK technique."""
        return self.TECHNIQUE_MAP.get(detection.name)

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

    def generate_navigator_layer(self, detections: list[Detection]) -> dict:
        """Generate an ATT&CK Navigator layer JSON."""
        techniques = []
        seen = set()

        for det in detections:
            mapping = self.map_detection(det)
            if mapping and mapping["id"] not in seen:
                seen.add(mapping["id"])
                color = "#ff0000" if det.severity.value == "critical" else "#ff6600" if det.severity.value == "warning" else "#ffcc00"
                techniques.append({
                    "techniqueID": mapping["id"],
                    "color": color,
                    "comment": det.description,
                    "enabled": True,
                })

        return {
            "name": "Deep View Forensic Analysis",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Techniques detected by Deep View forensic analysis",
            "techniques": techniques,
        }
