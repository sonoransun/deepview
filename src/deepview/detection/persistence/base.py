"""Persistence detector base types."""
from __future__ import annotations

import enum
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class PersistenceSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PersistenceArtifact(BaseModel):
    """A single persistence mechanism discovery.

    ``mechanism`` identifies the family (``cron``, ``systemd``, ``launchd``,
    ``registry_run``, ``k8s_cronjob``, ...). ``location`` is the
    human-readable source (file path, registry key, K8s manifest path).
    """

    mechanism: str
    location: str
    mitre_technique: str = ""
    description: str = ""
    severity: PersistenceSeverity = PersistenceSeverity.MEDIUM
    last_modified: datetime | None = None
    content_hash: str = ""
    owning_user: str = ""
    command: str = ""  # normalised "what gets executed"
    suspicious_reasons: list[str] = Field(default_factory=list)
    deviation_from_baseline: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash for dedup between runs and for baseline comparison."""
        parts = [self.mechanism, self.location, self.command, self.content_hash]
        return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()


class PersistenceDetector(ABC):
    """Base class for platform-specific persistence collectors."""

    #: A short human-readable platform identifier.
    platform: str = ""

    @abstractmethod
    def scan(self, *, include_user_scope: bool = True) -> list[PersistenceArtifact]:
        """Enumerate persistence artifacts on the current host."""

    # ------------------------------------------------------------------
    # Shared helpers usable by subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: Path) -> str:
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _mtime(path: Path) -> datetime | None:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return None

    @staticmethod
    def _owner(path: Path) -> str:
        try:
            st = path.stat()
        except OSError:
            return ""
        try:
            import pwd

            return pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            return str(st.st_uid)
