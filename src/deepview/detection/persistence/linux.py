"""Linux persistence collectors.

Covers the mechanisms most commonly abused by attackers on Linux hosts:
cron / at, systemd units + timers, shell init files, SSH authorized_keys,
PAM configuration, dynamic loader hooks, kernel modules, udev rules, and
initramfs tampering. Each collector is resilient to missing files and
returns an empty list rather than raising.

Many collectors accept a ``root`` override so tests can point them at a
sandboxed fixture directory.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from deepview.core.logging import get_logger
from deepview.detection.persistence.base import (
    PersistenceArtifact,
    PersistenceDetector,
    PersistenceSeverity,
)

log = get_logger("detection.persistence.linux")

# Writable / untrustworthy path prefixes that should raise suspicion when
# they appear in a systemd ``ExecStart=`` or cron command.
_SUSPICIOUS_PATH_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/home/",
    "/root/.cache/",
)


class LinuxPersistenceDetector(PersistenceDetector):
    platform = "linux"

    def __init__(self, root: Path | str = "/") -> None:
        self.root = Path(root)

    def scan(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        findings.extend(self.scan_cron())
        findings.extend(self.scan_systemd())
        findings.extend(self.scan_shell_init(include_user_scope=include_user_scope))
        findings.extend(self.scan_ssh_authorized_keys(include_user_scope=include_user_scope))
        findings.extend(self.scan_pam())
        findings.extend(self.scan_dynamic_loader())
        findings.extend(self.scan_kernel_modules())
        findings.extend(self.scan_udev_rules())
        return findings

    # ------------------------------------------------------------------
    # Cron / at
    # ------------------------------------------------------------------

    def scan_cron(self) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        cron_roots = [
            self.root / "etc/crontab",
            self.root / "etc/cron.d",
            self.root / "etc/cron.daily",
            self.root / "etc/cron.hourly",
            self.root / "etc/cron.weekly",
            self.root / "etc/cron.monthly",
            self.root / "var/spool/cron",
            self.root / "var/spool/cron/crontabs",
        ]
        for path in cron_roots:
            if not path.exists():
                continue
            if path.is_file():
                findings.extend(self._cron_file(path))
            else:
                for entry in _safe_iterdir(path):
                    if entry.is_file():
                        findings.extend(self._cron_file(entry))
        return findings

    def _cron_file(self, path: Path) -> list[PersistenceArtifact]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        findings: list[PersistenceArtifact] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            reasons: list[str] = []
            if any(clean.endswith(suffix) or suffix in clean for suffix in (" base64 ", "curl ", "wget ", "nc ", "/bin/sh -c")):
                reasons.append("downloads or pipes remote content")
            if any(prefix in clean for prefix in _SUSPICIOUS_PATH_PREFIXES):
                reasons.append("executes from user/world-writable path")
            findings.append(
                PersistenceArtifact(
                    mechanism="cron",
                    location=f"{path}:{line_no}",
                    mitre_technique="T1053.003",
                    description=f"cron job in {path.name}",
                    severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                    last_modified=self._mtime(path),
                    content_hash=self._hash_file(path),
                    owning_user=self._owner(path),
                    command=clean,
                    suspicious_reasons=reasons,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # systemd
    # ------------------------------------------------------------------

    _EXEC_START = re.compile(r"^ExecStart\s*=\s*(.+)$", re.MULTILINE)

    def scan_systemd(self) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        unit_roots = [
            self.root / "etc/systemd/system",
            self.root / "usr/lib/systemd/system",
            self.root / "lib/systemd/system",
            self.root / "run/systemd/system",
        ]
        for base in unit_roots:
            if not base.exists():
                continue
            for unit in _safe_rglob(base, "*.service"):
                findings.extend(self._systemd_unit(unit, kind="service"))
            for timer in _safe_rglob(base, "*.timer"):
                findings.extend(self._systemd_unit(timer, kind="timer"))
        return findings

    def _systemd_unit(self, path: Path, kind: str) -> list[PersistenceArtifact]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        findings: list[PersistenceArtifact] = []
        for match in self._EXEC_START.finditer(text):
            command = match.group(1).strip()
            reasons: list[str] = []
            for prefix in _SUSPICIOUS_PATH_PREFIXES:
                if prefix in command:
                    reasons.append(f"ExecStart under {prefix}")
            if command.startswith("-"):
                reasons.append("ExecStart uses leading '-' (ignore-failure)")
            findings.append(
                PersistenceArtifact(
                    mechanism=f"systemd_{kind}",
                    location=str(path),
                    mitre_technique="T1543.002",
                    description=f"systemd {kind} unit",
                    severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                    last_modified=self._mtime(path),
                    content_hash=self._hash_file(path),
                    owning_user=self._owner(path),
                    command=command,
                    suspicious_reasons=reasons,
                    evidence={"exec_start": command},
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Shell init / dotfiles
    # ------------------------------------------------------------------

    _SHELL_INIT_SYSTEM = (
        "etc/profile",
        "etc/bashrc",
        "etc/bash.bashrc",
        "etc/zshrc",
        "etc/zsh/zshrc",
        "etc/zsh/zprofile",
    )
    _SHELL_INIT_USER = (
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".bash_logout",
    )

    def scan_shell_init(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        for rel in self._SHELL_INIT_SYSTEM:
            path = self.root / rel
            findings.extend(self._shell_init_file(path, "system"))
        if include_user_scope:
            for home in self._user_homes():
                for name in self._SHELL_INIT_USER:
                    findings.extend(self._shell_init_file(home / name, "user"))
        return findings

    def _shell_init_file(self, path: Path, scope: str) -> list[PersistenceArtifact]:
        if not path.exists() or not path.is_file():
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        reasons: list[str] = []
        if "curl" in text and "|" in text:
            reasons.append("curl piped into shell")
        if "LD_PRELOAD" in text:
            reasons.append("sets LD_PRELOAD")
        if "base64 -d" in text or "base64 --decode" in text:
            reasons.append("runs base64-decoded payload")
        if not reasons:
            return []
        return [
            PersistenceArtifact(
                mechanism=f"shell_init_{scope}",
                location=str(path),
                mitre_technique="T1546.004",
                description="shell init file contains persistence payload",
                severity=PersistenceSeverity.HIGH,
                last_modified=self._mtime(path),
                content_hash=self._hash_file(path),
                owning_user=self._owner(path),
                command=_first_matching_line(text, ("curl", "LD_PRELOAD", "base64")),
                suspicious_reasons=reasons,
            )
        ]

    # ------------------------------------------------------------------
    # SSH
    # ------------------------------------------------------------------

    def scan_ssh_authorized_keys(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        if include_user_scope:
            for home in self._user_homes():
                path = home / ".ssh" / "authorized_keys"
                if not path.is_file():
                    continue
                try:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for line_no, line in enumerate(lines, start=1):
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    reasons: list[str] = []
                    if "command=" in clean:
                        reasons.append("force-command option")
                    if "from=" in clean and "127.0.0.1" not in clean:
                        reasons.append("from= restriction (non-local)")
                    findings.append(
                        PersistenceArtifact(
                            mechanism="ssh_authorized_keys",
                            location=f"{path}:{line_no}",
                            mitre_technique="T1098.004",
                            description="SSH authorized key",
                            severity=PersistenceSeverity.HIGH if reasons else PersistenceSeverity.MEDIUM,
                            last_modified=self._mtime(path),
                            content_hash=self._hash_file(path),
                            owning_user=self._owner(path),
                            command=clean.split()[-1] if clean.split() else "",
                            suspicious_reasons=reasons,
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # PAM
    # ------------------------------------------------------------------

    _PAM_SUSPICIOUS = {"pam_exec.so", "pam_python.so", "pam_script.so"}

    def scan_pam(self) -> list[PersistenceArtifact]:
        base = self.root / "etc/pam.d"
        if not base.exists():
            return []
        findings: list[PersistenceArtifact] = []
        for entry in _safe_iterdir(base):
            if not entry.is_file():
                continue
            try:
                text = entry.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                module = next((tok for tok in clean.split() if tok.endswith(".so")), "")
                if module in self._PAM_SUSPICIOUS:
                    findings.append(
                        PersistenceArtifact(
                            mechanism="pam",
                            location=f"{entry}:{line_no}",
                            mitre_technique="T1556.003",
                            description=f"{module} invoked from PAM stack",
                            severity=PersistenceSeverity.HIGH,
                            last_modified=self._mtime(entry),
                            content_hash=self._hash_file(entry),
                            owning_user=self._owner(entry),
                            command=clean,
                            suspicious_reasons=[f"{module} allows arbitrary code"],
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # Dynamic loader
    # ------------------------------------------------------------------

    def scan_dynamic_loader(self) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        preload = self.root / "etc/ld.so.preload"
        if preload.is_file():
            try:
                text = preload.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if text.strip():
                findings.append(
                    PersistenceArtifact(
                        mechanism="ld_so_preload",
                        location=str(preload),
                        mitre_technique="T1574.006",
                        description="/etc/ld.so.preload contains entries",
                        severity=PersistenceSeverity.CRITICAL,
                        last_modified=self._mtime(preload),
                        content_hash=self._hash_file(preload),
                        owning_user=self._owner(preload),
                        command=text.strip(),
                        suspicious_reasons=["ld.so.preload is the classic LD_PRELOAD rootkit loader"],
                    )
                )
        conf_dir = self.root / "etc/ld.so.conf.d"
        if conf_dir.exists():
            for entry in _safe_iterdir(conf_dir):
                if not entry.is_file():
                    continue
                findings.append(
                    PersistenceArtifact(
                        mechanism="ld_so_conf",
                        location=str(entry),
                        mitre_technique="T1574.006",
                        description="ld.so.conf.d entry",
                        severity=PersistenceSeverity.LOW,
                        last_modified=self._mtime(entry),
                        content_hash=self._hash_file(entry),
                        owning_user=self._owner(entry),
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Kernel modules
    # ------------------------------------------------------------------

    def scan_kernel_modules(self) -> list[PersistenceArtifact]:
        findings: list[PersistenceArtifact] = []
        for base_rel in ("etc/modules-load.d", "etc/modprobe.d", "etc/modules"):
            base = self.root / base_rel
            if not base.exists():
                continue
            paths = [base] if base.is_file() else list(_safe_iterdir(base))
            for entry in paths:
                if not entry.is_file():
                    continue
                findings.append(
                    PersistenceArtifact(
                        mechanism="kernel_module_config",
                        location=str(entry),
                        mitre_technique="T1547.006",
                        description="kernel module auto-load config",
                        severity=PersistenceSeverity.MEDIUM,
                        last_modified=self._mtime(entry),
                        content_hash=self._hash_file(entry),
                        owning_user=self._owner(entry),
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # udev
    # ------------------------------------------------------------------

    def scan_udev_rules(self) -> list[PersistenceArtifact]:
        base = self.root / "etc/udev/rules.d"
        if not base.exists():
            return []
        findings: list[PersistenceArtifact] = []
        for entry in _safe_iterdir(base):
            if not entry.is_file():
                continue
            try:
                text = entry.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "RUN+=" not in text and "RUN=" not in text:
                continue
            findings.append(
                PersistenceArtifact(
                    mechanism="udev_rule",
                    location=str(entry),
                    mitre_technique="T1546",
                    description="udev rule invokes an external program on device events",
                    severity=PersistenceSeverity.HIGH,
                    last_modified=self._mtime(entry),
                    content_hash=self._hash_file(entry),
                    owning_user=self._owner(entry),
                    command=_first_matching_line(text, ("RUN+=",)),
                    suspicious_reasons=["RUN+= invokes an external program"],
                )
            )
        return findings

    # ------------------------------------------------------------------

    def _user_homes(self) -> Iterable[Path]:
        passwd = self.root / "etc/passwd"
        if not passwd.is_file():
            return []
        homes: list[Path] = []
        try:
            lines = passwd.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line in lines:
            parts = line.split(":")
            if len(parts) < 6:
                continue
            home = parts[5]
            if not home:
                continue
            if home.startswith("/"):
                candidate = self.root / home.lstrip("/")
            else:
                candidate = self.root / home
            if candidate.exists():
                homes.append(candidate)
        return homes


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


def _first_matching_line(text: str, needles: tuple[str, ...]) -> str:
    for line in text.splitlines():
        if any(needle in line for needle in needles):
            return line.strip()
    return ""
