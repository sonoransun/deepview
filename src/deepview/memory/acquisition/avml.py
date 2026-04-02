"""AVML memory acquisition provider for Linux."""
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

log = get_logger("memory.acquisition.avml")


class AVMLProvider(MemoryAcquisitionProvider):
    """Memory acquisition using Microsoft's AVML tool."""

    @classmethod
    def provider_name(cls) -> str:
        return "avml"

    def is_available(self) -> bool:
        try:
            find_tool("avml")
            return True
        except ToolNotFoundError:
            return False

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def acquire(self, target: AcquisitionTarget, output: Path,
                fmt: DumpFormat = DumpFormat.RAW) -> AcquisitionResult:
        avml_path = find_tool("avml")
        start = time.time()

        args = [str(avml_path), str(output)]
        if fmt == DumpFormat.LIME:
            args.insert(1, "--format=lime")

        log.info("acquiring", tool="avml", output=str(output))
        result = run_command(args, timeout=600)

        if not result.success:
            raise AcquisitionError(f"AVML failed: {result.stderr}")

        return make_result(output, fmt, start)
