"""OSXPmem memory acquisition provider for macOS."""
from __future__ import annotations
import time
from pathlib import Path

from deepview.core.types import (
    Platform, PrivilegeLevel, DumpFormat,
    AcquisitionTarget, AcquisitionResult,
)
from deepview.core.exceptions import AcquisitionError, ToolNotFoundError
from deepview.core.logging import get_logger
from deepview.interfaces.acquisition import MemoryAcquisitionProvider
from deepview.utils.process import find_tool, run_command
from deepview.memory.acquisition.base import make_result

log = get_logger("memory.acquisition.osxpmem")


class OSXPmemProvider(MemoryAcquisitionProvider):
    @classmethod
    def provider_name(cls) -> str:
        return "osxpmem"

    def is_available(self) -> bool:
        try:
            find_tool("osxpmem")
            return True
        except ToolNotFoundError:
            return False

    def supported_platforms(self) -> list[Platform]:
        return [Platform.MACOS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def acquire(self, target: AcquisitionTarget, output: Path,
                fmt: DumpFormat = DumpFormat.RAW) -> AcquisitionResult:
        osxpmem = find_tool("osxpmem")
        start = time.time()

        result = run_command([str(osxpmem), "-o", str(output)], timeout=600)
        if not result.success:
            raise AcquisitionError(f"OSXPmem failed: {result.stderr}")

        return make_result(output, fmt, start)
