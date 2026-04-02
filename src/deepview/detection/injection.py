"""Process injection detection covering MITRE T1055 sub-techniques."""
from __future__ import annotations
from dataclasses import dataclass, field
from deepview.core.logging import get_logger
from deepview.core.types import EventSeverity
from deepview.detection.anti_forensics import Detection

log = get_logger("detection.injection")

# MITRE T1055 sub-techniques
INJECTION_TECHNIQUES = {
    "T1055.001": "Dynamic-link Library Injection",
    "T1055.002": "Portable Executable Injection",
    "T1055.003": "Thread Execution Hijacking",
    "T1055.004": "Asynchronous Procedure Call",
    "T1055.005": "Thread Local Storage",
    "T1055.008": "Ptrace System Calls",
    "T1055.009": "Proc Memory",
    "T1055.011": "Extra Window Memory Injection",
    "T1055.012": "Process Hollowing",
    "T1055.013": "Process Doppelganging",
    "T1055.014": "VDSO Hijacking",
    "T1055.015": "ListPlanting",
}


class InjectionDetector:
    """Detect process injection techniques in memory."""

    def __init__(self):
        self._detections: list[Detection] = []

    def detect_hollow_processes(self, processes: list[dict]) -> list[Detection]:
        """Detect process hollowing (T1055.012).

        Signs: PEB ImageBaseAddress doesn't match the actual mapped image,
        or the main module's on-disk hash doesn't match in-memory hash.
        """
        detections = []
        for proc in processes:
            peb_base = proc.get("peb_image_base", 0)
            actual_base = proc.get("actual_image_base", 0)

            if peb_base and actual_base and peb_base != actual_base:
                detections.append(Detection(
                    name="PROCESS_HOLLOWING",
                    severity=EventSeverity.CRITICAL,
                    description=(
                        f"Process {proc.get('name', '?')} (PID {proc.get('pid', '?')}): "
                        f"PEB base {hex(peb_base)} != actual base {hex(actual_base)}"
                    ),
                    pid=proc.get("pid", 0),
                    process_name=proc.get("name", ""),
                    technique="T1055.012",
                    evidence=proc,
                ))

        self._detections.extend(detections)
        return detections

    def detect_injected_code(self, vad_entries: list[dict]) -> list[Detection]:
        """Detect injected code regions via VAD analysis.

        Signs: VAD entries with PAGE_EXECUTE_READWRITE that are not
        backed by a file (anonymous executable memory).
        """
        detections = []
        for vad in vad_entries:
            protection = vad.get("protection", "")
            is_private = vad.get("private", False)
            has_file = vad.get("file_object", None)

            if "EXECUTE" in protection and "WRITE" in protection and not has_file and is_private:
                detections.append(Detection(
                    name="INJECTED_CODE",
                    severity=EventSeverity.WARNING,
                    description=(
                        f"Suspicious RWX memory at {hex(vad.get('start', 0))}-{hex(vad.get('end', 0))} "
                        f"in PID {vad.get('pid', '?')} ({vad.get('process', '?')})"
                    ),
                    pid=vad.get("pid", 0),
                    process_name=vad.get("process", ""),
                    offset=vad.get("start", 0),
                    technique="T1055",
                    evidence=vad,
                ))

        self._detections.extend(detections)
        return detections

    def detect_suspicious_threads(self, threads: list[dict]) -> list[Detection]:
        """Detect suspicious thread start addresses.

        Signs: Thread start address outside any known module's range.
        """
        detections = []
        for thread in threads:
            start_addr = thread.get("start_address", 0)
            in_module = thread.get("in_known_module", True)

            if start_addr and not in_module:
                detections.append(Detection(
                    name="SUSPICIOUS_THREAD",
                    severity=EventSeverity.WARNING,
                    description=(
                        f"Thread {thread.get('tid', '?')} in PID {thread.get('pid', '?')} "
                        f"has start address {hex(start_addr)} outside known modules"
                    ),
                    pid=thread.get("pid", 0),
                    technique="T1055.003",
                    evidence=thread,
                ))

        self._detections.extend(detections)
        return detections

    def detect_peb_masquerade(self, processes: list[dict]) -> list[Detection]:
        """Detect PEB masquerading.

        Signs: PEB command line or image path doesn't match the actual binary.
        """
        detections = []
        for proc in processes:
            peb_path = proc.get("peb_image_path", "")
            actual_path = proc.get("actual_image_path", "")

            if peb_path and actual_path and peb_path.lower() != actual_path.lower():
                detections.append(Detection(
                    name="PEB_MASQUERADE",
                    severity=EventSeverity.CRITICAL,
                    description=(
                        f"PID {proc.get('pid', '?')}: PEB path '{peb_path}' != actual '{actual_path}'"
                    ),
                    pid=proc.get("pid", 0),
                    process_name=proc.get("name", ""),
                    technique="T1036.005",
                    evidence=proc,
                ))

        self._detections.extend(detections)
        return detections

    @property
    def all_detections(self) -> list[Detection]:
        return list(self._detections)
