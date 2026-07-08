"""Live memory access provider."""
from __future__ import annotations
import time
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.events import MemoryAcquiredEvent
from deepview.core.types import (
    Platform, PrivilegeLevel, DumpFormat,
    AcquisitionTarget, AcquisitionResult,
)
from deepview.core.exceptions import AcquisitionError
from deepview.core.logging import get_logger
from deepview.core.platform import detect_platform
from deepview.interfaces.acquisition import MemoryAcquisitionProvider
from deepview.memory.acquisition.base import make_result

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("memory.acquisition.live")

LIVE_SOURCES = ["/proc/kcore", "/dev/mem", "/dev/crash"]


class LiveMemoryProvider(MemoryAcquisitionProvider):
    """Direct live memory access via /proc/kcore or /dev/mem."""

    def __init__(self, context: AnalysisContext | None = None) -> None:
        self._context = context

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

        # Copy memory source to output file. A read error mid-stream (e.g. a
        # reserved/PCI hole under CONFIG_STRICT_DEVMEM) truncates the image; we
        # record that rather than certifying a partial dump as complete.
        chunk_size = 1024 * 1024  # 1 MiB
        truncated = False
        read_error = ""
        bytes_written = 0
        with open(source, "rb") as src, open(output, "wb") as dst:
            while True:
                try:
                    chunk = src.read(chunk_size)
                except (IOError, OSError) as e:
                    truncated = True
                    read_error = f"{type(e).__name__} at offset {bytes_written}: {e}"
                    log.warning("live_read_error", offset=bytes_written, error=read_error)
                    break
                if not chunk:
                    break  # clean EOF
                dst.write(chunk)
                bytes_written += len(chunk)

        result_obj = make_result(
            output, fmt, start, truncated=truncated, read_error=read_error, method="live"
        )
        if self._context is not None:
            self._context.events.publish(
                MemoryAcquiredEvent(
                    path=str(output),
                    dump_format=fmt,
                    size_bytes=result_obj.size_bytes,
                )
            )
        return result_obj
