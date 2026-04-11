"""DTrace monitoring backend for macOS."""
from __future__ import annotations
import asyncio
import json
import time
from collections.abc import AsyncIterator

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.core.exceptions import BackendNotAvailableError
from deepview.tracing.events import MonitorEvent, exec_event
from deepview.tracing.filters import FilterExpr, split_for_pushdown
from deepview.tracing.providers.base import ProbeSpec, FilterPushDownResult, BackendStats
from deepview.utils.process import find_tool

log = get_logger("tracing.providers.dtrace")


class DTraceBackend:
    """macOS monitoring backend using DTrace subprocess."""

    def __init__(self):
        self._proc: asyncio.subprocess.Process | None = None
        self._running = False
        self._event_queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=65536)
        self._stats = BackendStats()
        self._start_time = 0.0
        self._available = False

        try:
            find_tool("dtrace")
            self._available = True
        except Exception:
            log.debug("dtrace_not_available")

    @property
    def platform(self) -> str:
        return "darwin"

    @property
    def backend_name(self) -> str:
        return "dtrace"

    async def start(self, probes: list[ProbeSpec]) -> None:
        if not self._available:
            raise BackendNotAvailableError("DTrace is not available")

        script = self._generate_dtrace_script(probes)

        self._proc = await asyncio.create_subprocess_exec(
            "sudo", "dtrace", "-n", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._running = True
        self._start_time = time.time()

        # Start reading output
        asyncio.create_task(self._read_output())
        log.info("dtrace_started", probes=len(probes))

    async def stop(self) -> None:
        self._running = False
        if self._proc:
            self._proc.terminate()
            await self._proc.wait()
            self._proc = None
        log.info("dtrace_stopped")

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

    def _generate_dtrace_script(self, probes: list[ProbeSpec]) -> str:
        """Generate DTrace D script from probe specs."""
        lines = []
        want_syscall = False
        want_exec = False
        want_signal = False
        for probe in probes:
            if probe.category in (EventCategory.SYSCALL_RAW, EventCategory.FILE_IO, EventCategory.FILE_ACCESS):
                want_syscall = True
            if probe.category in (EventCategory.PROCESS, EventCategory.PROCESS_EXEC):
                want_exec = True
            if probe.category in (EventCategory.SIGNAL, EventCategory.PTRACE):
                want_signal = True
        if want_syscall:
            lines.append(
                'syscall:::entry '
                '{ printf("DVE|syscall|%d|%d|%d|%s|%s\\n", pid, tid, ppid, execname, probefunc); }'
            )
        if want_exec:
            lines.append(
                'proc:::exec-success '
                '{ printf("DVE|exec|%d|%d|%d|%s|%s\\n", pid, tid, ppid, execname, probefunc); }'
            )
        if want_signal:
            lines.append(
                'proc:::signal-send '
                '{ printf("DVE|signal|%d|%d|%d|%s|%d\\n", pid, tid, ppid, execname, args[2]); }'
            )
        if not lines:
            lines.append(
                'syscall:::entry '
                '{ printf("DVE|syscall|%d|%d|%d|%s|%s\\n", pid, tid, ppid, execname, probefunc); }'
            )
        return "\n".join(lines)

    async def _read_output(self) -> None:
        """Read and parse DTrace output lines."""
        if not self._proc or not self._proc.stdout:
            return

        while self._running:
            try:
                line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=1.0)
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                if decoded.startswith("DVE|"):
                    event = self._parse_event(decoded)
                    if event:
                        self._stats.events_received += 1
                        try:
                            self._event_queue.put_nowait(event)
                        except asyncio.QueueFull:
                            self._stats.events_dropped += 1
            except asyncio.TimeoutError:
                continue
            except Exception:
                if not self._running:
                    break

    def _parse_event(self, line: str) -> MonitorEvent | None:
        """Parse a DVE| formatted line into a MonitorEvent.

        New line format: ``DVE|<kind>|<pid>|<tid>|<ppid>|<comm>|<detail>``
        where ``kind`` is one of ``syscall`` / ``exec`` / ``signal``.
        """
        try:
            parts = line.split("|")
            if len(parts) < 7:
                return None
            kind = parts[1]
            proc = ProcessContext(
                pid=int(parts[2]),
                tid=int(parts[3]),
                ppid=int(parts[4]),
                uid=0,
                gid=0,
                comm=parts[5],
            )
            source = EventSource(platform="darwin", backend="dtrace", probe_name=kind)
            ts = time.time_ns()
            if kind == "exec":
                return exec_event(
                    process=proc,
                    argv=[parts[6]],
                    source=source,
                    timestamp_ns=ts,
                )
            if kind == "signal":
                return MonitorEvent(
                    timestamp_ns=ts,
                    category=EventCategory.SIGNAL,
                    source=source,
                    process=proc,
                    syscall_name="signal",
                    args={"signal": int(parts[6]) if parts[6].isdigit() else 0},
                )
            return MonitorEvent(
                timestamp_ns=ts,
                category=EventCategory.SYSCALL_RAW,
                source=source,
                process=proc,
                syscall_name=parts[6],
            )
        except (ValueError, IndexError):
            return None
