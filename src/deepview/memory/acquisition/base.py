"""Base acquisition utilities."""
from __future__ import annotations
import time
from datetime import datetime, timezone
from pathlib import Path

from deepview.core.types import AcquisitionResult, DumpFormat
from deepview.utils.hashing import hash_file


def make_result(
    output: Path,
    fmt: DumpFormat,
    start_time: float,
    *,
    algorithm: str = "sha256",
    truncated: bool = False,
    bytes_expected: int = 0,
    read_error: str = "",
    method: str = "",
    write_manifest: bool = True,
) -> AcquisitionResult:
    """Create an AcquisitionResult with digest, timing, and provenance.

    When *write_manifest* is true a chain-of-custody sidecar is written next to
    the image. *truncated* / *read_error* record whether the capture completed;
    a truncated image is still hashed, but the flag prevents it being certified
    as a complete acquisition.
    """
    from deepview import __version__ as _dv_version

    result = AcquisitionResult(
        success=True,
        output_path=output,
        format=fmt,
        size_bytes=output.stat().st_size,
        duration_seconds=time.time() - start_time,
        hash_sha256=hash_file(output, algorithm),
        algorithm=algorithm,
        acquired_at=datetime.now(timezone.utc).isoformat(),
        tool_version=_dv_version,
        truncated=truncated,
        bytes_expected=bytes_expected,
        read_error=read_error,
    )

    if write_manifest:
        from deepview.utils.manifest import write_acquisition_manifest

        result.manifest_path = write_acquisition_manifest(result, method=method)

    return result
