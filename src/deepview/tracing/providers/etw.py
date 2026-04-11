"""ETW monitoring backend for Windows."""
from __future__ import annotations
import asyncio
import time
from collections.abc import AsyncIterator

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory
from deepview.core.exceptions import BackendNotAvailableError
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr
from deepview.tracing.providers.base import ProbeSpec, FilterPushDownResult, BackendStats

log = get_logger("tracing.providers.etw")


class ETWBackend:
    """Windows ETW monitoring backend (stub).

    Full implementation would use pywintrace or ctypes bindings
    to subscribe to kernel ETW providers:
    - Microsoft-Windows-Kernel-Process
    - Microsoft-Windows-Kernel-File
    - Microsoft-Windows-Kernel-Network
    """

    KERNEL_PROVIDERS = {
        EventCategory.PROCESS: "Microsoft-Windows-Kernel-Process",
        EventCategory.FILE_IO: "Microsoft-Windows-Kernel-File",
        EventCategory.NETWORK: "Microsoft-Windows-Kernel-Network",
        EventCategory.MEMORY: "Microsoft-Windows-Kernel-Memory",
    }

    def __init__(self):
        self._running = False
        self._stats = BackendStats()
        self._start_time = 0.0

    @property
    def platform(self) -> str:
        return "windows"

    @property
    def backend_name(self) -> str:
        return "etw"

    async def start(self, probes: list[ProbeSpec]) -> None:
        import sys
        if sys.platform != "win32":
            raise BackendNotAvailableError("ETW is only available on Windows")
        self._running = True
        self._start_time = time.time()
        log.info("etw_started")

    async def stop(self) -> None:
        self._running = False
        log.info("etw_stopped")

    async def events(self) -> AsyncIterator[MonitorEvent]:
        while self._running:
            await asyncio.sleep(1.0)
            return
            yield  # type: ignore[misc]

    def apply_filter(self, filter_expr: FilterExpr) -> FilterPushDownResult:
        return FilterPushDownResult()

    def get_stats(self) -> BackendStats:
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return self._stats
