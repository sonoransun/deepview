"""macOS persistence collectors.

Focus on Apple-specific mechanisms: LaunchDaemons / LaunchAgents,
login items (``backgrounditems.btm``), Configuration Profiles, cron
(legacy), kexts and System Extensions, DYLD_* variables, and TCC
database grants.
"""
from __future__ import annotations

import os
import plistlib
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger
from deepview.detection.persistence.base import (
    PersistenceArtifact,
    PersistenceDetector,
    PersistenceSeverity,
)

log = get_logger("detection.persistence.macos")


class MacOSPersistenceDetector(PersistenceDetector):
    platform = "darwin"

    _LAUNCH_DIRS = (
        "Library/LaunchDaemons",
        "Library/LaunchAgents",
        "System/Library/LaunchDaemons",
        "System/Library/LaunchAgents",
    )
    _USER_LAUNCH_DIR = "Library/LaunchAgents"

    def __init__(self, root: Path | str = "/") -> None:
        self.root = Path(root)

    def scan(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        findings.extend(self.scan_launch_items(include_user_scope=include_user_scope))
        findings.extend(self.scan_configuration_profiles())
        findings.extend(self.scan_cron())
        findings.extend(self.scan_tcc())
        findings.extend(self.scan_dyld_hooks())
        return findings

    # ------------------------------------------------------------------

    def scan_launch_items(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        dirs = [self.root / d for d in self._LAUNCH_DIRS]
        if include_user_scope:
            for home in self._user_homes():
                dirs.append(home / self._USER_LAUNCH_DIR)
        for base in dirs:
            if not base.exists() or not base.is_dir():
                continue
            for plist in _safe_rglob(base, "*.plist"):
                findings.extend(self._launch_plist(plist))
        return findings

    def _launch_plist(self, path: Path) -> list[PersistenceArtifact]:
        try:
            with path.open("rb") as fh:
                data = plistlib.load(fh)
        except Exception:
            return []
        if not isinstance(data, dict):
            return []
        label = str(data.get("Label", path.stem))
        program = data.get("Program") or (data.get("ProgramArguments") or [None])[0] or ""
        program_args = data.get("ProgramArguments") or []
        run_at_load = bool(data.get("RunAtLoad", False))
        keep_alive = bool(data.get("KeepAlive", False))
        command = program if isinstance(program, str) else ""
        if isinstance(program_args, list) and program_args:
            command = " ".join(str(p) for p in program_args)
        reasons: list[str] = []
        if command and any(
            prefix in command for prefix in ("/tmp/", "/Users/Shared/", "/private/tmp/")
        ):
            reasons.append("Program path in user/world-writable location")
        if keep_alive and run_at_load:
            reasons.append("RunAtLoad + KeepAlive = boot persistence")
        kind = "launch_daemon" if "/LaunchDaemons/" in str(path) else "launch_agent"
        return [
            PersistenceArtifact(
                mechanism=kind,
                location=str(path),
                mitre_technique="T1543.001" if kind == "launch_agent" else "T1543.004",
                description=f"{kind} {label}",
                severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                last_modified=self._mtime(path),
                content_hash=self._hash_file(path),
                owning_user=self._owner(path),
                command=command,
                suspicious_reasons=reasons,
                evidence={"run_at_load": run_at_load, "keep_alive": keep_alive},
            )
        ]

    # ------------------------------------------------------------------

    def scan_configuration_profiles(self) -> list[PersistenceArtifact]:
        paths = [
            self.root / "Library/Managed Preferences",
            self.root / "var/db/ConfigurationProfiles/Store",
        ]
        findings: list[PersistenceArtifact] = []
        for base in paths:
            if not base.exists():
                continue
            for plist in _safe_rglob(base, "*.plist"):
                findings.append(
                    PersistenceArtifact(
                        mechanism="config_profile",
                        location=str(plist),
                        mitre_technique="T1556",
                        description="MDM / Configuration Profile",
                        severity=PersistenceSeverity.MEDIUM,
                        last_modified=self._mtime(plist),
                        content_hash=self._hash_file(plist),
                        owning_user=self._owner(plist),
                    )
                )
        return findings

    # ------------------------------------------------------------------

    def scan_cron(self) -> list[PersistenceArtifact]:
        spool = self.root / "var/at/tabs"
        if not spool.exists():
            return []
        findings: list[PersistenceArtifact] = []
        for entry in _safe_iterdir(spool):
            if entry.is_file():
                findings.append(
                    PersistenceArtifact(
                        mechanism="cron_macos",
                        location=str(entry),
                        mitre_technique="T1053.003",
                        description="Legacy cron tab",
                        severity=PersistenceSeverity.MEDIUM,
                        last_modified=self._mtime(entry),
                        content_hash=self._hash_file(entry),
                        owning_user=self._owner(entry),
                    )
                )
        return findings

    # ------------------------------------------------------------------

    def scan_tcc(self) -> list[PersistenceArtifact]:
        """Scan user TCC databases for suspicious grants.

        TCC is stored in SQLite; we only open it read-only. If the file is
        unreadable (SIP protection), we skip gracefully.
        """
        import sqlite3

        findings: list[PersistenceArtifact] = []
        tcc_paths = [
            self.root / "Library/Application Support/com.apple.TCC/TCC.db",
        ]
        for home in self._user_homes():
            tcc_paths.append(home / "Library/Application Support/com.apple.TCC/TCC.db")
        for path in tcc_paths:
            if not path.is_file():
                continue
            try:
                conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            except sqlite3.DatabaseError:
                continue
            try:
                cursor = conn.execute(
                    "SELECT service, client, auth_value FROM access WHERE auth_value > 0"
                )
                for service, client, auth in cursor:
                    if service in ("kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility", "kTCCServiceScreenCapture"):
                        findings.append(
                            PersistenceArtifact(
                                mechanism="tcc_grant",
                                location=f"{path}:{client}:{service}",
                                mitre_technique="T1548.003",
                                description=f"TCC grant: {client} -> {service}",
                                severity=PersistenceSeverity.HIGH,
                                evidence={"service": service, "client": client, "auth": auth},
                            )
                        )
            except sqlite3.Error:
                pass
            finally:
                conn.close()
        return findings

    # ------------------------------------------------------------------

    def scan_dyld_hooks(self) -> list[PersistenceArtifact]:
        """Inspect launchd plists for DYLD_* environment injection."""
        findings: list[PersistenceArtifact] = []
        for base in (self.root / d for d in self._LAUNCH_DIRS):
            if not base.exists():
                continue
            for plist in _safe_rglob(base, "*.plist"):
                try:
                    data = plistlib.loads(plist.read_bytes())
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                env = data.get("EnvironmentVariables") or {}
                if not isinstance(env, dict):
                    continue
                for key, value in env.items():
                    if str(key).startswith("DYLD_"):
                        findings.append(
                            PersistenceArtifact(
                                mechanism="dyld_insertion",
                                location=f"{plist}:{key}",
                                mitre_technique="T1574.006",
                                description=f"{key} set in {plist.name}",
                                severity=PersistenceSeverity.CRITICAL,
                                last_modified=self._mtime(plist),
                                content_hash=self._hash_file(plist),
                                command=str(value),
                                suspicious_reasons=[f"{key} overrides dyld search"],
                            )
                        )
        return findings

    # ------------------------------------------------------------------

    def _user_homes(self) -> list[Path]:
        base = self.root / "Users"
        if not base.exists():
            return []
        return [p for p in _safe_iterdir(base) if p.is_dir() and not p.name.startswith(".")]


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir())
    except OSError:
        return []


def _safe_rglob(path: Path, pattern: str) -> list[Path]:
    try:
        return sorted(path.rglob(pattern))
    except OSError:
        return []
