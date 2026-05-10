"""WinPmem memory acquisition provider for Windows."""
from __future__ import annotations
import time
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.events import MemoryAcquiredEvent
from deepview.core.types import (
    Platform, PrivilegeLevel, DumpFormat,
    AcquisitionTarget, AcquisitionResult,
)
from deepview.core.exceptions import AcquisitionError, ToolNotFoundError
from deepview.core.logging import get_logger
from deepview.interfaces.acquisition import MemoryAcquisitionProvider
from deepview.utils.process import find_tool, run_command
from deepview.memory.acquisition.base import make_result

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("memory.acquisition.winpmem")


class WinPmemProvider(MemoryAcquisitionProvider):
    def __init__(self, context: AnalysisContext | None = None) -> None:
        self._context = context

    @classmethod
    def provider_name(cls) -> str:
        return "winpmem"

    def is_available(self) -> bool:
        try:
            find_tool("winpmem")
            return True
        except ToolNotFoundError:
            return False

    def supported_platforms(self) -> list[Platform]:
        return [Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def acquire(self, target: AcquisitionTarget, output: Path,
                fmt: DumpFormat = DumpFormat.RAW) -> AcquisitionResult:
        winpmem = find_tool("winpmem")
        start = time.time()

        result = run_command([str(winpmem), str(output)], timeout=600)
        if not result.success:
            raise AcquisitionError(f"WinPmem failed: {result.stderr}")

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
