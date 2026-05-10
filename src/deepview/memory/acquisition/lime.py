"""LiME memory acquisition provider for Linux."""
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
from deepview.interfaces.acquisition import MemoryAcquisitionProvider
from deepview.utils.process import run_command
from deepview.memory.acquisition.base import make_result

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("memory.acquisition.lime")


class LiMEProvider(MemoryAcquisitionProvider):
    """Memory acquisition using LiME kernel module."""

    def __init__(self, context: AnalysisContext | None = None) -> None:
        self._context = context

    @classmethod
    def provider_name(cls) -> str:
        return "lime"

    def is_available(self) -> bool:
        # Check if LiME module is loadable
        result = run_command(["modinfo", "lime"], timeout=10)
        return result.success

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def acquire(self, target: AcquisitionTarget, output: Path,
                fmt: DumpFormat = DumpFormat.LIME) -> AcquisitionResult:
        start = time.time()

        format_str = "lime" if fmt == DumpFormat.LIME else "raw"

        log.info("acquiring", tool="lime", output=str(output), format=format_str)

        # Load LiME kernel module
        result = run_command([
            "insmod", "lime.ko",
            f"path={output}",
            f"format={format_str}",
        ], timeout=600)

        if not result.success:
            raise AcquisitionError(f"LiME insmod failed: {result.stderr}")

        # Unload module
        run_command(["rmmod", "lime"], timeout=30)

        result_obj = make_result(output, fmt, start)
        if self._context is not None:
            self._context.events.publish(
                MemoryAcquiredEvent(
                    path=str(output),
                    dump_format=fmt,
                    size_bytes=result_obj.size_bytes,
                )
            )
        return result_obj
