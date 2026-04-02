"""Live memory access provider."""
from __future__ import annotations
import shutil
import time
from pathlib import Path

from deepview.core.types import (
    Platform, PrivilegeLevel, DumpFormat,
    AcquisitionTarget, AcquisitionResult,
)
from deepview.core.exceptions import AcquisitionError
from deepview.core.logging import get_logger
from deepview.core.platform import detect_platform
from deepview.interfaces.acquisition import MemoryAcquisitionProvider
from deepview.memory.acquisition.base import make_result

log = get_logger("memory.acquisition.live")

LIVE_SOURCES = ["/proc/kcore", "/dev/mem", "/dev/crash"]


class LiveMemoryProvider(MemoryAcquisitionProvider):
    """Direct live memory access via /proc/kcore or /dev/mem."""

    @classmethod
    def provider_name(cls) -> str:
        return "live"

    def is_available(self) -> bool:
        if detect_platform() != Platform.LINUX:
            return False
        import os
        return any(os.access(src, os.R_OK) for src in LIVE_SOURCES)

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def _find_source(self) -> str:
        import os
        for src in LIVE_SOURCES:
            if os.access(src, os.R_OK):
                return src
        raise AcquisitionError("No live memory source available")

    def acquire(self, target: AcquisitionTarget, output: Path,
                fmt: DumpFormat = DumpFormat.RAW) -> AcquisitionResult:
        source = self._find_source()
        start = time.time()

        log.info("acquiring_live", source=source, output=str(output))

        # Copy memory source to output file
        chunk_size = 1024 * 1024  # 1 MiB
        with open(source, "rb") as src, open(output, "wb") as dst:
            while True:
                try:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                except (IOError, OSError):
                    break  # Expected at end of readable memory

        return make_result(output, fmt, start)
