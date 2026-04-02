"""Base acquisition utilities."""
from __future__ import annotations
import time
from pathlib import Path

from deepview.core.types import AcquisitionResult, DumpFormat
from deepview.utils.hashing import hash_file


def make_result(output: Path, fmt: DumpFormat, start_time: float) -> AcquisitionResult:
    """Create a successful AcquisitionResult with hash and timing."""
    return AcquisitionResult(
        success=True,
        output_path=output,
        format=fmt,
        size_bytes=output.stat().st_size,
        duration_seconds=time.time() - start_time,
        hash_sha256=hash_file(output),
    )
