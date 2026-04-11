"""Windows ETW monitoring backend.

This implementation uses ``ctypes`` to drive the
Event Tracing for Windows user-mode consumer APIs (``StartTraceW``,
``OpenTraceW``, ``ProcessTrace``, ``ControlTraceW``), subscribes to the
kernel providers most relevant for forensic work, and emits enriched
``MonitorEvent`` objects via the factories in ``tracing.events``.

Off-Windows the module imports cleanly but ``is_available()`` returns
``False`` and calling ``start()`` raises ``BackendNotAvailableError`` so
unit tests on macOS / Linux don't try to actually trace.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

from deepview.core.exceptions import BackendNotAvailableError, ProbeAttachError
from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.tracing.events import (
    MonitorEvent,
    exec_event,
    file_access_event,
    module_load_event,
    network_connect_event,
)
from deepview.tracing.filters import FilterExpr, split_for_pushdown
from deepview.tracing.providers.base import BackendStats, FilterPushDownResult, ProbeSpec

log = get_logger("tracing.providers.etw")


# Kernel providers we subscribe to. These are GUIDs for well-known
# Microsoft ETW providers — they are referenced by name elsewhere in the
# codebase for readability, then resolved to GUIDs via a mapping at start time.
KERNEL_PROVIDERS: dict[EventCategory, str] = {
    EventCategory.PROCESS_EXEC: "Microsoft-Windows-Kernel-Process",
    EventCategory.PROCESS: "Microsoft-Windows-Kernel-Process",
    EventCategory.FILE_ACCESS: "Microsoft-Windows-Kernel-File",
    EventCategory.FILE_IO: "Microsoft-Windows-Kernel-File",
    EventCategory.NETWORK_CONNECT: "Microsoft-Windows-Kernel-Network",
    EventCategory.NETWORK: "Microsoft-Windows-Kernel-Network",
    EventCategory.REGISTRY: "Microsoft-Windows-Kernel-Registry",
    EventCategory.MODULE_LOAD: "Microsoft-Windows-Kernel-Image",
    EventCategory.DNS: "Microsoft-Windows-DNS-Client",
}

# Security-relevant secondary providers (not strictly kernel)
EXTRA_PROVIDERS = [
    "Microsoft-Windows-Threat-Intelligence",  # requires PPL; enriched security events
    "Microsoft-Windows-PowerShell",            # script-block logging
    "Microsoft-Windows-WMI-Activity",          # T1546.003 WMI sub
]


class ETWBackend:
    """Windows ETW live tracing backend (ctypes + Advapi32)."""

    def __init__(self) -> None:
        self._running = False
        self._stats = BackendStats()
        self._start_time = 0.0
        self._event_queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=65536)
        self._poll_thread: threading.Thread | None = None
        self._session_handle: int = 0
        self._available = sys.platform == "win32"
        self._advapi32: Any = None
        self._tdh: Any = None
        self._providers: list[str] = []

    # ------------------------------------------------------------------
    # Backend protocol
    # ------------------------------------------------------------------

    @property
    def platform(self) -> str:
        return "windows"

    @property
    def backend_name(self) -> str:
        return "etw"

    def is_available(self) -> bool:
        return self._available

    async def start(self, probes: list[ProbeSpec]) -> None:
        if not self._available:
            raise BackendNotAvailableError("ETW is only available on Windows")
        try:
            import ctypes

            self._advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
            self._tdh = ctypes.windll.tdh  # type: ignore[attr-defined]
        except Exception as exc:
            raise BackendNotAvailableError(f"Failed to load ETW libraries: {exc}") from exc

        self._providers = self._select_providers(probes)
        try:
            self._session_handle = self._start_session(self._providers)
        except OSError as exc:
            raise ProbeAttachError(f"Failed to start ETW session: {exc}") from exc

        self._running = True
        self._start_time = time.time()
        self._poll_thread = threading.Thread(target=self._consume_loop, daemon=True)
        self._poll_thread.start()
        log.info("etw_started", providers=self._providers)

    async def stop(self) -> None:
        self._running = False
        if self._session_handle and self._advapi32 is not None:
            try:
                self._advapi32.ControlTraceW(
                    self._session_handle, None, None, 1
                )  # EVENT_TRACE_CONTROL_STOP
            except Exception:
                log.exception("etw_stop_failed")
            self._session_handle = 0
        if self._poll_thread:
            self._poll_thread.join(timeout=5.0)
        log.info("etw_stopped")

    async def events(self) -> AsyncIterator[MonitorEvent]:
        while self._running or not self._event_queue.empty():
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue

    def apply_filter(self, filter_expr: FilterExpr) -> FilterPushDownResult:
        # ETW filtering at the provider level is limited; we push PID and
        # keyword filters if present, everything else stays user-space.
        pushed, remaining = split_for_pushdown(
            filter_expr, supported_fields={"process.pid", "category"}
        )
        return FilterPushDownResult(pushed=pushed, remaining=remaining)

    def get_stats(self) -> BackendStats:
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return self._stats

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _select_providers(self, probes: list[ProbeSpec]) -> list[str]:
        providers: set[str] = set()
        for probe in probes:
            if probe.category in KERNEL_PROVIDERS:
                providers.add(KERNEL_PROVIDERS[probe.category])
        # Always add the Threat-Intelligence provider when any probe is requested;
        # it is the single best source of anti-tamper signals on Windows.
        if providers:
            providers.add("Microsoft-Windows-Threat-Intelligence")
        else:
            providers.add("Microsoft-Windows-Kernel-Process")
        return sorted(providers)

    def _start_session(self, providers: list[str]) -> int:
        """Start an ETW session and return its handle.

        Keeps the ctypes plumbing local so the rest of the backend stays
        readable. The real implementation lives in _etw_native so it can be
        swapped for a pywintrace binding without touching this class.
        """
        from deepview.tracing.providers import etw_native  # lazy

        return etw_native.start_session("DeepViewETW", providers)

    def _consume_loop(self) -> None:
        """Poll the ETW processing loop and publish events onto the queue."""
        from deepview.tracing.providers import etw_native  # lazy

        def on_event(raw: dict[str, Any]) -> None:
            evt = self._decode(raw)
            if evt is None:
                return
            self._stats.events_received += 1
            try:
                self._event_queue.put_nowait(evt)
            except asyncio.QueueFull:
                self._stats.events_dropped += 1

        try:
            etw_native.process_trace(self._session_handle, on_event, lambda: self._running)
        except Exception:  # pragma: no cover — Windows-only path
            log.exception("etw_processing_failed")

    def _decode(self, raw: dict[str, Any]) -> MonitorEvent | None:
        """Decode a raw provider event into a typed MonitorEvent."""
        provider = str(raw.get("provider", ""))
        opcode = str(raw.get("opcode", "")).lower()
        pid = int(raw.get("pid", 0))
        ppid = int(raw.get("ppid", 0))
        tid = int(raw.get("tid", 0))
        comm = str(raw.get("image_name", ""))
        ts = int(raw.get("timestamp_ns", time.time_ns()))
        proc = ProcessContext(pid=pid, tid=tid, ppid=ppid, comm=comm)
        source = EventSource(platform="windows", backend="etw", probe_name=provider)

        if "Kernel-Process" in provider and opcode in ("start", "processstart"):
            return exec_event(
                process=proc,
                argv=list(raw.get("argv", [])),
                envp=raw.get("envp"),
                interpreter=str(raw.get("parent_image", "")),
                source=source,
                timestamp_ns=ts,
            )
        if "Kernel-File" in provider:
            return file_access_event(
                process=proc,
                path=str(raw.get("filename", "")),
                operation=opcode or "open",
                source=source,
                timestamp_ns=ts,
            )
        if "Kernel-Network" in provider:
            return network_connect_event(
                process=proc,
                protocol=str(raw.get("protocol", "tcp")),
                src_ip=str(raw.get("src_ip", "")),
                src_port=int(raw.get("src_port", 0)),
                dst_ip=str(raw.get("dst_ip", "")),
                dst_port=int(raw.get("dst_port", 0)),
                direction="outbound",
                source=source,
                timestamp_ns=ts,
            )
        if "Kernel-Image" in provider:
            return module_load_event(
                process=proc,
                module_name=str(raw.get("image_name", "")),
                module_path=str(raw.get("image_path", "")),
                kind="driver",
                source=source,
                timestamp_ns=ts,
            )
        if "Threat-Intelligence" in provider:
            return MonitorEvent(
                timestamp_ns=ts,
                category=EventCategory.MEMORY,
                severity=EventSeverity.WARNING,
                source=source,
                process=proc,
                syscall_name=opcode,
                args=dict(raw),
                tags=["threat_intelligence"],
            )
        if "DNS-Client" in provider:
            return MonitorEvent(
                timestamp_ns=ts,
                category=EventCategory.DNS,
                source=source,
                process=proc,
                syscall_name="dns_query",
                args={"name": raw.get("query_name", ""), "type": raw.get("query_type", "")},
                tags=["dns"],
            )
        return None
