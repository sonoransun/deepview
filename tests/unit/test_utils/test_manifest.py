"""Tests for evidence manifest / chain-of-custody records."""
from __future__ import annotations

import json

from deepview.core.types import AcquisitionResult, DumpFormat
from deepview.utils.manifest import (
    EvidenceManifest,
    build_acquisition_manifest,
    manifest_path_for,
    write_acquisition_manifest,
    write_manifest,
)


def _result(tmp_path, truncated=False):
    img = tmp_path / "image.raw"
    img.write_bytes(b"x" * 32)
    return AcquisitionResult(
        success=True,
        output_path=img,
        format=DumpFormat.RAW,
        size_bytes=32,
        hash_sha256="abc123",
        algorithm="sha256",
        acquired_at="2026-07-08T00:00:00+00:00",
        tool_version="0.1.0",
        truncated=truncated,
        read_error="hole" if truncated else "",
    )


def test_manifest_path_for():
    from pathlib import Path

    assert manifest_path_for(Path("/e/img.raw")).name == "img.raw.manifest.json"


def test_build_acquisition_manifest_captures_provenance(tmp_path):
    manifest = build_acquisition_manifest(_result(tmp_path), method="live")
    assert isinstance(manifest, EvidenceManifest)
    assert manifest.tool == "deepview"
    assert manifest.tool_version == "0.1.0"
    assert manifest.created_utc  # populated
    art = manifest.artifacts[0]
    assert art.digest == "abc123"
    assert art.algorithm == "sha256"
    assert art.source_method == "live"
    assert art.truncated is False


def test_write_manifest_roundtrip(tmp_path):
    manifest = build_acquisition_manifest(_result(tmp_path))
    out = tmp_path / "m.json"
    write_manifest(manifest, out)
    data = json.loads(out.read_text())
    assert data["tool"] == "deepview"
    assert data["artifacts"][0]["digest"] == "abc123"


def test_write_acquisition_manifest_sidecar(tmp_path):
    result = _result(tmp_path, truncated=True)
    path = write_acquisition_manifest(result, method="live")
    assert path is not None and path.exists()
    assert path.name == "image.raw.manifest.json"
    data = json.loads(path.read_text())
    assert data["artifacts"][0]["truncated"] is True
    assert "hole" in data["artifacts"][0]["read_error"]


def test_write_acquisition_manifest_none_without_output():
    result = AcquisitionResult(success=True, format=DumpFormat.RAW)
    assert write_acquisition_manifest(result) is None
