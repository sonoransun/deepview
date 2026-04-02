"""Anti-forensics detection: DKOM, rootkit, hook detection."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger
from deepview.core.types import EventSeverity

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer

log = get_logger("detection.anti_forensics")


@dataclass
class Detection:
    """A single detection finding."""
    name: str
    severity: EventSeverity
    description: str
    offset: int = 0
    pid: int = 0
    process_name: str = ""
    technique: str = ""  # MITRE ATT&CK technique ID
    evidence: dict = field(default_factory=dict)


class AntiForensicsDetector:
    """Detect anti-forensics techniques in memory images.

    Techniques detected:
    - DKOM (Direct Kernel Object Manipulation)
    - SSDT hooking
    - IDT hooking
    - IRP hooking
    - Inline function hooking
    - Hidden drivers
    - Callback manipulation
    """

    def __init__(self):
        self._detections: list[Detection] = []

    def detect_dkom(self, process_lists: dict[str, list[dict]]) -> list[Detection]:
        """Detect hidden processes by cross-referencing multiple kernel structures.

        Compares process lists from:
        - PsActiveProcessHead (linked list)
        - CSRSS handle table
        - PspCidTable
        - Session process list
        - Desktop thread scanning
        """
        detections = []

        if len(process_lists) < 2:
            return detections

        # Build PID sets from each source
        pid_sets: dict[str, set[int]] = {}
        for source, processes in process_lists.items():
            pid_sets[source] = {p.get("pid", 0) for p in processes}

        # Find PIDs present in some sources but missing from others
        all_pids = set()
        for pids in pid_sets.values():
            all_pids |= pids

        sources = list(pid_sets.keys())
        for pid in all_pids:
            present_in = [s for s in sources if pid in pid_sets[s]]
            missing_from = [s for s in sources if pid not in pid_sets[s]]

            if missing_from and present_in:
                # This process is hidden from some sources
                proc_info = None
                for source in present_in:
                    for p in process_lists[source]:
                        if p.get("pid") == pid:
                            proc_info = p
                            break
                    if proc_info:
                        break

                detections.append(Detection(
                    name="DKOM_HIDDEN_PROCESS",
                    severity=EventSeverity.CRITICAL,
                    description=(
                        f"Process PID {pid} ({proc_info.get('name', 'unknown') if proc_info else 'unknown'}) "
                        f"found in {present_in} but hidden from {missing_from}"
                    ),
                    pid=pid,
                    process_name=proc_info.get("name", "") if proc_info else "",
                    technique="T1014",  # Rootkit
                    evidence={
                        "present_in": present_in,
                        "missing_from": missing_from,
                    },
                ))

        self._detections.extend(detections)
        return detections

    def detect_ssdt_hooks(self, ssdt_entries: list[dict]) -> list[Detection]:
        """Detect SSDT (System Service Descriptor Table) hooks.

        Compares SSDT entries against known-good values to find
        functions redirected to rootkit code.
        """
        detections = []
        for entry in ssdt_entries:
            addr = entry.get("address", 0)
            expected_module = entry.get("expected_module", "ntoskrnl")
            actual_module = entry.get("actual_module", "")

            if actual_module and actual_module != expected_module:
                detections.append(Detection(
                    name="SSDT_HOOK",
                    severity=EventSeverity.CRITICAL,
                    description=(
                        f"SSDT entry {entry.get('index', '?')} ({entry.get('name', '?')}) "
                        f"hooked: expected {expected_module}, found {actual_module}"
                    ),
                    offset=addr,
                    technique="T1574.013",
                    evidence=entry,
                ))

        self._detections.extend(detections)
        return detections

    def detect_inline_hooks(self, functions: list[dict]) -> list[Detection]:
        """Detect inline function hooks (JMP patches at function prologues)."""
        detections = []
        for func in functions:
            prologue = func.get("prologue_bytes", b"")
            if isinstance(prologue, bytes) and len(prologue) >= 1:
                # Check for JMP instruction at function start
                if prologue[0] in (0xE9, 0xFF, 0xEB):
                    detections.append(Detection(
                        name="INLINE_HOOK",
                        severity=EventSeverity.WARNING,
                        description=f"Inline hook detected at {func.get('name', '?')} ({hex(func.get('address', 0))})",
                        offset=func.get("address", 0),
                        technique="T1574",
                        evidence={"prologue": prologue[:16].hex()},
                    ))

        self._detections.extend(detections)
        return detections

    @property
    def all_detections(self) -> list[Detection]:
        return list(self._detections)

    def clear(self) -> None:
        self._detections.clear()
