"""Evidence manifest / chain-of-custody provenance records.

A manifest is a hashed, timestamped, operator- and tool-attributed record written
alongside acquired evidence. It makes an acquired image authenticable and
reproducible: an examiner (or a court) can later confirm which tool/version,
operator, and host produced an artifact, its digest and size, and whether the
capture was complete or truncated.
"""
from __future__ import annotations

import getpass
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from deepview.core.types import AcquisitionResult
from deepview.core.platform import detect_platform


class ArtifactRecord(BaseModel):
    """Integrity record for a single acquired artifact."""

    path: str
    size_bytes: int = 0
    algorithm: str = "sha256"
    digest: str = ""
    acquired_utc: str = ""
    truncated: bool = False
    read_error: str = ""
    source_method: str = ""


class EvidenceManifest(BaseModel):
    """Chain-of-custody manifest for one or more acquired artifacts."""

    tool: str = "deepview"
    tool_version: str = ""
    created_utc: str = ""
    operator: str = ""
    host: str = ""
    platform: str = ""
    command: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactRecord] = Field(default_factory=list)


def _operator() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return ""


def _host() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def manifest_path_for(output: Path) -> Path:
    """Sidecar manifest path for an evidence file (``image.raw.manifest.json``)."""
    output = Path(output)
    return output.with_name(output.name + ".manifest.json")


def build_acquisition_manifest(result: AcquisitionResult, *, method: str = "") -> EvidenceManifest:
    """Build an EvidenceManifest from a completed AcquisitionResult."""
    artifact = ArtifactRecord(
        path=str(result.output_path) if result.output_path else "",
        size_bytes=result.size_bytes,
        algorithm=result.algorithm,
        digest=result.hash_sha256,
        acquired_utc=result.acquired_at,
        truncated=result.truncated,
        read_error=result.read_error,
        source_method=method,
    )
    return EvidenceManifest(
        tool="deepview",
        tool_version=result.tool_version,
        created_utc=_now_utc(),
        operator=_operator(),
        host=_host(),
        platform=str(detect_platform().value),
        command=list(sys.argv),
        artifacts=[artifact],
    )


def write_manifest(manifest: EvidenceManifest, path: Path) -> Path:
    """Write a manifest as pretty-printed JSON; returns the written path."""
    path = Path(path)
    path.write_text(json.dumps(manifest.model_dump(mode="json"), indent=2), encoding="utf-8")
    return path


def write_acquisition_manifest(result: AcquisitionResult, *, method: str = "") -> Path | None:
    """Write a sidecar manifest next to an acquired image; None if no output."""
    if not result.output_path:
        return None
    manifest = build_acquisition_manifest(result, method=method)
    return write_manifest(manifest, manifest_path_for(Path(result.output_path)))
