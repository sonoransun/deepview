"""Timestomping detector.

Flags filesystem timestamps that are physically impossible or that bear the
fingerprint of ``touch -t`` / anti-forensic utilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


@dataclass
class TimestompFinding:
    path: str
    reason: str
    severity: str = "medium"
    evidence: dict[str, str] = field(default_factory=dict)


@dataclass
class FileTimes:
    path: str
    atime: datetime | None = None
    mtime: datetime | None = None
    ctime: datetime | None = None  # inode change time (Linux)
    crtime: datetime | None = None  # creation / birth time
    fn_mtime: datetime | None = None  # NTFS $FILE_NAME mtime
    fn_ctime: datetime | None = None  # NTFS $FILE_NAME ctime
    fn_crtime: datetime | None = None  # NTFS $FILE_NAME creation


class TimestompingDetector:
    """Heuristics across NTFS / ext4 / APFS to spot inconsistent timestamps."""

    def __init__(self, *, now: datetime | None = None) -> None:
        self._now = now or datetime.now(timezone.utc)

    def scan(self, entries: Iterable[FileTimes]) -> list[TimestompFinding]:
        findings: list[TimestompFinding] = []
        for ft in entries:
            findings.extend(self._check(ft))
        return findings

    def _check(self, ft: FileTimes) -> list[TimestompFinding]:
        out: list[TimestompFinding] = []
        # NTFS: $FILE_NAME timestamps should be *older* than $STANDARD_INFORMATION;
        # if they are *newer*, someone edited the visible timestamps.
        if ft.fn_mtime and ft.mtime and ft.fn_mtime > ft.mtime:
            out.append(
                TimestompFinding(
                    path=ft.path,
                    reason="NTFS $FILE_NAME mtime newer than $STANDARD_INFORMATION mtime",
                    severity="high",
                    evidence={
                        "fn_mtime": ft.fn_mtime.isoformat(),
                        "si_mtime": ft.mtime.isoformat(),
                    },
                )
            )
        if ft.fn_crtime and ft.crtime and ft.fn_crtime > ft.crtime:
            out.append(
                TimestompFinding(
                    path=ft.path,
                    reason="NTFS $FILE_NAME birthtime newer than $STANDARD_INFORMATION birthtime",
                    severity="high",
                    evidence={
                        "fn_crtime": ft.fn_crtime.isoformat(),
                        "si_crtime": ft.crtime.isoformat(),
                    },
                )
            )
        # ext4: inode change time (ctime) must never be older than content change time
        # (mtime). If it is, someone rolled the mtime backward.
        if ft.ctime and ft.mtime and ft.ctime < ft.mtime:
            out.append(
                TimestompFinding(
                    path=ft.path,
                    reason="ext4 ctime earlier than mtime — physically impossible",
                    severity="high",
                    evidence={
                        "ctime": ft.ctime.isoformat(),
                        "mtime": ft.mtime.isoformat(),
                    },
                )
            )
        # Zero-precision artifacts: touch -t leaves timestamps with exact zero
        # fractional seconds. A cluster of zero-precision times on one host is
        # highly unusual.
        if ft.mtime and ft.mtime.microsecond == 0 and ft.mtime.second == 0:
            out.append(
                TimestompFinding(
                    path=ft.path,
                    reason="mtime has zero fractional seconds (touch -t fingerprint)",
                    severity="low",
                    evidence={"mtime": ft.mtime.isoformat()},
                )
            )
        # Future-dated files — anything >24h beyond "now" is always suspicious.
        for label, value in (("mtime", ft.mtime), ("ctime", ft.ctime), ("crtime", ft.crtime)):
            if value is None:
                continue
            if (value - self._now).total_seconds() > 86400:
                out.append(
                    TimestompFinding(
                        path=ft.path,
                        reason=f"{label} is more than 24h in the future",
                        severity="medium",
                        evidence={label: value.isoformat()},
                    )
                )
        return out
