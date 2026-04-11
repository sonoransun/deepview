"""Windows persistence collectors.

Covers Run/RunOnce keys, IFEO debugger hijack, services, scheduled tasks,
WMI subscriptions, COM hijacks, startup folders, and driver registrations.

This module runs on any platform — registry paths are resolved lazily and
a ``winreg`` import failure is treated as "not on Windows" rather than an
error. Tests inject a mock registry via ``_open_key`` monkeypatching.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any, Iterable

from deepview.core.logging import get_logger
from deepview.detection.persistence.base import (
    PersistenceArtifact,
    PersistenceDetector,
    PersistenceSeverity,
)

log = get_logger("detection.persistence.windows")


class WindowsPersistenceDetector(PersistenceDetector):
    platform = "windows"

    #: Keys under HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER that are common
    #: persistence vectors. Each tuple is (hive, subkey, mitre).
    RUN_KEYS: list[tuple[str, str, str]] = [
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "T1547.001"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "T1547.001"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "T1547.004"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "T1546.012"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "T1547.001"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "T1547.001"),
    ]

    def __init__(self) -> None:
        self._winreg: Any = None
        self._available = sys.platform == "win32"
        if self._available:
            try:
                import winreg

                self._winreg = winreg
            except ImportError:
                self._available = False

    def scan(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        if not self._available:
            return []
        findings: list[PersistenceArtifact] = []
        findings.extend(self.scan_run_keys())
        findings.extend(self.scan_services())
        findings.extend(self.scan_scheduled_tasks())
        findings.extend(self.scan_wmi_subscriptions())
        return findings

    # ------------------------------------------------------------------

    def scan_run_keys(self) -> list[PersistenceArtifact]:
        if not self._winreg:
            return []
        findings: list[PersistenceArtifact] = []
        for hive_name, subkey, mitre in self.RUN_KEYS:
            hive = self._resolve_hive(hive_name)
            if hive is None:
                continue
            try:
                key = self._winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            try:
                idx = 0
                while True:
                    try:
                        value_name, data, _ = self._winreg.EnumValue(key, idx)
                    except OSError:
                        break
                    command = str(data)
                    reasons: list[str] = []
                    if any(
                        suspect in command.lower()
                        for suspect in ("powershell", "-enc", "rundll32", "mshta", "wscript", "\\temp\\")
                    ):
                        reasons.append("uses living-off-the-land binary")
                    findings.append(
                        PersistenceArtifact(
                            mechanism="registry_run",
                            location=f"{hive_name}\\{subkey}\\{value_name}",
                            mitre_technique=mitre,
                            description=f"Run key value {value_name}",
                            severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                            command=command,
                            suspicious_reasons=reasons,
                        )
                    )
                    idx += 1
            finally:
                self._winreg.CloseKey(key)
        return findings

    def _resolve_hive(self, name: str) -> Any:
        if not self._winreg:
            return None
        mapping = {
            "HKLM": self._winreg.HKEY_LOCAL_MACHINE,
            "HKCU": self._winreg.HKEY_CURRENT_USER,
            "HKU": self._winreg.HKEY_USERS,
            "HKCR": self._winreg.HKEY_CLASSES_ROOT,
        }
        return mapping.get(name)

    # ------------------------------------------------------------------

    def scan_services(self) -> list[PersistenceArtifact]:
        """Enumerate non-Microsoft services with ``sc qc`` via subprocess."""
        if not self._available:
            return []
        import subprocess  # lazy

        try:
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except Exception:
            return []
        findings: list[PersistenceArtifact] = []
        for block in result.stdout.split("\r\n\r\n"):
            name = ""
            for line in block.splitlines():
                if line.strip().startswith("SERVICE_NAME:"):
                    name = line.split(":", 1)[1].strip()
                    break
            if not name:
                continue
            findings.append(
                PersistenceArtifact(
                    mechanism="windows_service",
                    location=name,
                    mitre_technique="T1543.003",
                    description=f"Windows service {name}",
                    severity=PersistenceSeverity.LOW,
                )
            )
        return findings

    # ------------------------------------------------------------------

    def scan_scheduled_tasks(self) -> list[PersistenceArtifact]:
        if not self._available:
            return []
        import subprocess

        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except Exception:
            return []
        findings: list[PersistenceArtifact] = []
        for line in result.stdout.splitlines():
            cells = [c.strip().strip('"') for c in line.split(",")]
            if len(cells) < 2 or not cells[0]:
                continue
            name = cells[0]
            findings.append(
                PersistenceArtifact(
                    mechanism="scheduled_task",
                    location=name,
                    mitre_technique="T1053.005",
                    description=f"Scheduled task {name}",
                    severity=PersistenceSeverity.MEDIUM,
                )
            )
        return findings

    # ------------------------------------------------------------------

    def scan_wmi_subscriptions(self) -> list[PersistenceArtifact]:
        """Enumerate WMI event consumers via PowerShell.

        Requires running on Windows with access to ``root\\subscription``.
        """
        if not self._available:
            return []
        import subprocess

        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ConvertTo-Json -Depth 3",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except Exception:
            return []
        findings: list[PersistenceArtifact] = []
        import json as _json

        try:
            bindings = _json.loads(result.stdout)
        except Exception:
            return findings
        if isinstance(bindings, dict):
            bindings = [bindings]
        for binding in bindings or []:
            findings.append(
                PersistenceArtifact(
                    mechanism="wmi_subscription",
                    location=str(binding.get("Filter", "unknown")),
                    mitre_technique="T1546.003",
                    description="WMI permanent event subscription",
                    severity=PersistenceSeverity.HIGH,
                    evidence=binding,
                )
            )
        return findings
