"""macOS Endpoint Security tracing backend.

DTrace is deprecated on modern macOS. The supported path for live system
telemetry on macOS 11+ is the Endpoint Security framework. This backend
wraps an ES client that delivers ``ES_EVENT_TYPE_NOTIFY_*`` messages and
translates them to ``MonitorEvent``.

Implementation notes:

* The real ES client must run in a process with the
  ``com.apple.developer.endpoint-security.client`` entitlement; this is
  cumbersome outside a signed binary. Deep View therefore keeps the actual
  ES socket handling in a sibling helper (``_es_native.py``) that we stub
  here. Off-macOS the backend imports cleanly but returns
  ``is_available() == False``.

* Events landed here are enriched with real ``ProcessContext`` attributes:
  ES reports ``proc_info`` including cdhash, signing id, team id, and
  code signing flags. These go into :class:`SigningInfo`.
"""
from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import AsyncIterator
from typing import Any, Callable

from deepview.core.exceptions import BackendNotAvailableError
from deepview.core.logging import get_logger
from deepview.core.types import (
    EventCategory,
    EventSource,
    ProcessContext,
    SigningInfo,
)
from deepview.tracing.events import (
    MonitorEvent,
    exec_event,
    file_access_event,
    fork_event,
    module_load_event,
    ptrace_event,
    memory_map_event,
)
from deepview.tracing.filters import FilterExpr, split_for_pushdown
from deepview.tracing.providers.base import BackendStats, FilterPushDownResult, ProbeSpec

log = get_logger("tracing.providers.endpoint_security")


ES_EVENT_EXEC = "exec"
ES_EVENT_FORK = "fork"
ES_EVENT_OPEN = "open"
ES_EVENT_RENAME = "rename"
ES_EVENT_UNLINK = "unlink"
ES_EVENT_SIGNAL = "signal"
ES_EVENT_PROC_CHECK = "proc_check"
ES_EVENT_MMAP = "mmap"
ES_EVENT_KEXTLOAD = "kextload"


class EndpointSecurityBackend:
    """macOS ES backend with graceful degradation off-platform."""

    def __init__(self) -> None:
        self._running = False
        self._event_queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=65536)
        self._stats = BackendStats()
        self._start_time = 0.0
        self._client: Any = None
        self._available = sys.platform == "darwin"

    @property
    def platform(self) -> str:
        return "darwin"

    @property
    def backend_name(self) -> str:
        return "endpoint_security"

    def is_available(self) -> bool:
        return self._available

    async def start(self, probes: list[ProbeSpec]) -> None:
        if not self._available:
            raise BackendNotAvailableError(
                "Endpoint Security is only available on macOS"
            )
        try:
            from deepview.tracing.providers import es_native

            self._client = es_native.open_client(
                on_event=self._enqueue,
                subscribe=self._events_to_subscribe(probes),
            )
        except BackendNotAvailableError:
            raise
        except Exception as exc:
            raise BackendNotAvailableError(
                f"Failed to open Endpoint Security client (entitlement required?): {exc}"
            ) from exc
        self._running = True
        self._start_time = time.time()
        log.info("endpoint_security_started")

    async def stop(self) -> None:
        self._running = False
        if self._client is not None:
            try:
                from deepview.tracing.providers import es_native

                es_native.close_client(self._client)
            except Exception:
                log.exception("es_close_failed")
            self._client = None
        log.info("endpoint_security_stopped")

    async def events(self) -> AsyncIterator[MonitorEvent]:
        while self._running or not self._event_queue.empty():
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue

    def apply_filter(self, filter_expr: FilterExpr) -> FilterPushDownResult:
        pushed, remaining = split_for_pushdown(
            filter_expr, supported_fields={"process.pid"}
        )
        return FilterPushDownResult(pushed=pushed, remaining=remaining)

    def get_stats(self) -> BackendStats:
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return self._stats

    # ------------------------------------------------------------------

    def _events_to_subscribe(self, probes: list[ProbeSpec]) -> list[str]:
        mapping = {
            EventCategory.PROCESS_EXEC: ES_EVENT_EXEC,
            EventCategory.PROCESS_FORK: ES_EVENT_FORK,
            EventCategory.PROCESS: ES_EVENT_EXEC,
            EventCategory.FILE_ACCESS: ES_EVENT_OPEN,
            EventCategory.FILE_IO: ES_EVENT_OPEN,
            EventCategory.PTRACE: ES_EVENT_SIGNAL,
            EventCategory.MEMORY_MAP: ES_EVENT_MMAP,
            EventCategory.MEMORY: ES_EVENT_MMAP,
            EventCategory.MODULE_LOAD: ES_EVENT_KEXTLOAD,
        }
        subs: set[str] = set()
        for probe in probes:
            if probe.category in mapping:
                subs.add(mapping[probe.category])
        return sorted(subs) or [ES_EVENT_EXEC, ES_EVENT_OPEN]

    def _enqueue(self, raw: dict[str, Any]) -> None:
        event = self._decode(raw)
        if event is None:
            return
        self._stats.events_received += 1
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            self._stats.events_dropped += 1

    def _decode(self, raw: dict[str, Any]) -> MonitorEvent | None:
        kind = str(raw.get("event_type", ""))
        proc = self._process_from_raw(raw.get("process", {}))
        source = EventSource(
            platform="darwin", backend="endpoint_security", probe_name=kind
        )
        ts = int(raw.get("mach_time_ns", 0) or time.time_ns())

        if kind == ES_EVENT_EXEC:
            return exec_event(
                process=proc,
                argv=list(raw.get("argv", [])),
                envp=dict(raw.get("envp", {})),
                interpreter=str(raw.get("interpreter", "")),
                source=source,
                timestamp_ns=ts,
            )
        if kind == ES_EVENT_FORK:
            return fork_event(
                process=proc,
                child_pid=int(raw.get("child_pid", 0)),
                source=source,
                timestamp_ns=ts,
            )
        if kind in (ES_EVENT_OPEN, ES_EVENT_RENAME, ES_EVENT_UNLINK):
            return file_access_event(
                process=proc,
                path=str(raw.get("path", "")),
                operation=kind,
                new_path=str(raw.get("new_path", "")),
                source=source,
                timestamp_ns=ts,
            )
        if kind == ES_EVENT_SIGNAL and int(raw.get("signal", 0)) == 19:  # SIGSTOP debugger trick
            return ptrace_event(
                process=proc,
                target_pid=int(raw.get("target_pid", 0)),
                request=f"signal:{raw.get('signal', '')}",
                source=source,
                timestamp_ns=ts,
            )
        if kind == ES_EVENT_MMAP:
            return memory_map_event(
                process=proc,
                addr=int(raw.get("addr", 0)),
                length=int(raw.get("length", 0)),
                prot=str(raw.get("prot", "")),
                flags=str(raw.get("flags", "")),
                source=source,
                timestamp_ns=ts,
            )
        if kind == ES_EVENT_KEXTLOAD:
            return module_load_event(
                process=proc,
                module_name=str(raw.get("kext_identifier", "")),
                module_path=str(raw.get("kext_path", "")),
                kind="kext",
                source=source,
                timestamp_ns=ts,
            )
        return None

    def _process_from_raw(self, info: dict[str, Any]) -> ProcessContext:
        signing = SigningInfo(
            signed=bool(info.get("is_platform_binary", False) or info.get("cdhash")),
            team_id=str(info.get("team_id", "")),
            signer=str(info.get("signing_id", "")),
            verified=bool(info.get("is_es_client", False)),
        )
        return ProcessContext(
            pid=int(info.get("pid", 0)),
            tid=0,
            ppid=int(info.get("ppid", 0)),
            uid=int(info.get("ruid", 0)),
            gid=int(info.get("rgid", 0)),
            comm=str(info.get("executable_name", "")),
            exe_path=str(info.get("executable_path", "")),
            exe_hash_sha256=str(info.get("cdhash", "")),
            exe_signing=signing,
            auid=info.get("auid"),
            tty=str(info.get("tty", "")),
        )
