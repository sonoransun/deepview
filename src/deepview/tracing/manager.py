"""Trace subsystem orchestrator."""
from __future__ import annotations
import asyncio
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger
from deepview.core.platform import detect_platform
from deepview.core.types import Platform
from deepview.core.exceptions import MonitorError
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr
from deepview.tracing.stream import TraceEventBus, EventSubscription
from deepview.tracing.providers.base import ProbeSpec, MonitorBackend

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("tracing.manager")


class TraceManager:
    """Orchestrates system tracing across platforms."""

    def __init__(self, context: AnalysisContext):
        self._context = context
        self._backends: list[MonitorBackend] = []
        self._bus = TraceEventBus()
        self._running = False
        self._consumer_tasks: list[asyncio.Task] = []

    def _create_backends(self) -> list[MonitorBackend]:
        """Create platform-appropriate backends."""
        platform = detect_platform()
        backends = []

        if platform == Platform.LINUX:
            try:
                from deepview.tracing.providers.ebpf import EBPFBackend
                backend = EBPFBackend(
                    ring_buffer_pages=self._context.config.tracing.ring_buffer_pages,
                )
                if backend._available:
                    backends.append(backend)
            except Exception:
                pass
        elif platform == Platform.MACOS:
            try:
                from deepview.tracing.providers.dtrace import DTraceBackend
                backend = DTraceBackend()
                if backend._available:
                    backends.append(backend)
            except Exception:
                pass
        elif platform == Platform.WINDOWS:
            try:
                from deepview.tracing.providers.etw import ETWBackend
                backends.append(ETWBackend())
            except Exception:
                pass

        return backends

    async def start(self, probes: list[ProbeSpec], filter_expr: FilterExpr | None = None) -> None:
        """Start tracing with the given probes."""
        self._backends = self._create_backends()

        if not self._backends:
            raise MonitorError("No tracing backend available on this platform")

        for backend in self._backends:
            if filter_expr:
                result = backend.apply_filter(filter_expr)
                log.info("filter_pushdown",
                         backend=backend.backend_name,
                         pushed=len(result.pushed),
                         remaining=len(result.remaining))

            await backend.start(probes)
            task = asyncio.create_task(self._consume(backend))
            self._consumer_tasks.append(task)

        self._running = True
        log.info("tracing_started", backends=[b.backend_name for b in self._backends])

    async def stop(self) -> None:
        """Stop all tracing backends."""
        self._running = False

        for task in self._consumer_tasks:
            task.cancel()

        for backend in self._backends:
            await backend.stop()

        self._consumer_tasks.clear()
        self._backends.clear()
        log.info("tracing_stopped")

    async def _consume(self, backend: MonitorBackend) -> None:
        """Consume events from a backend and publish to the bus."""
        try:
            async for event in backend.events():
                await self._bus.publish(event)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("consumer_error", backend=backend.backend_name, error=str(e))

    def subscribe(self, filter_expr: FilterExpr | None = None) -> EventSubscription:
        """Subscribe to the trace event stream."""
        return self._bus.subscribe(filter_expr=filter_expr)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def available_backends(self) -> list[str]:
        backends = self._create_backends()
        return [b.backend_name for b in backends]
