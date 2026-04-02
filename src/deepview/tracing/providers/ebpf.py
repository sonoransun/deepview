"""BCC/eBPF monitoring backend for Linux."""
from __future__ import annotations
import asyncio
import time
import threading
from collections.abc import AsyncIterator
from typing import Any

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.core.exceptions import BackendNotAvailableError, ProbeAttachError
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr, FilterRule
from deepview.tracing.providers.base import ProbeSpec, FilterPushDownResult, BackendStats

log = get_logger("tracing.providers.ebpf")

# BPF C template for syscall tracing
BPF_TEMPLATE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    u64 timestamp_ns;
    char comm[16];
    int syscall_nr;
    long ret;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.ppid = task->real_parent->tgid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.syscall_nr = args->id;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class EBPFBackend:
    """Linux eBPF monitoring backend using BCC."""

    def __init__(self, ring_buffer_pages: int = 64):
        self._ring_buffer_pages = ring_buffer_pages
        self._bpf = None
        self._running = False
        self._poll_thread: threading.Thread | None = None
        self._event_queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=65536)
        self._stats = BackendStats()
        self._start_time = 0.0
        self._available = False

        try:
            from bcc import BPF
            self._BPF = BPF
            self._available = True
        except ImportError:
            log.debug("bcc_not_installed")

    @property
    def platform(self) -> str:
        return "linux"

    @property
    def backend_name(self) -> str:
        return "ebpf"

    async def start(self, probes: list[ProbeSpec]) -> None:
        if not self._available:
            raise BackendNotAvailableError("BCC is not installed")

        try:
            bpf_source = self._generate_bpf_source(probes)
            self._bpf = self._BPF(text=bpf_source)
            self._running = True
            self._start_time = time.time()

            # Set up perf buffer callback
            self._bpf["events"].open_perf_buffer(
                self._handle_event,
                page_cnt=self._ring_buffer_pages,
                lost_cb=self._handle_lost,
            )

            # Start polling thread
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()

            log.info("ebpf_started", probes=len(probes))
        except Exception as e:
            raise ProbeAttachError(f"Failed to start eBPF: {e}") from e

    async def stop(self) -> None:
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=5.0)
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None
        log.info("ebpf_stopped")

    async def events(self) -> AsyncIterator[MonitorEvent]:
        while self._running or not self._event_queue.empty():
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue

    def apply_filter(self, filter_expr: FilterExpr) -> FilterPushDownResult:
        # Basic: push PID filters into BPF, leave rest for user-space
        pushed = []
        remaining = []
        if hasattr(filter_expr, 'children'):
            for child in filter_expr.children:
                if isinstance(child, FilterRule) and child.field_path == "process.pid" and child.op == "eq":
                    pushed.append(child)
                else:
                    remaining.append(child)
        return FilterPushDownResult(pushed=pushed, remaining=remaining)

    def get_stats(self) -> BackendStats:
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return self._stats

    def _generate_bpf_source(self, probes: list[ProbeSpec]) -> str:
        """Generate BPF C source from probe specifications."""
        # For now, use the template for raw syscall tracing
        return BPF_TEMPLATE

    def _poll_loop(self) -> None:
        """Background thread polling the perf buffer."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                if not self._running:
                    break

    def _handle_event(self, cpu: int, data: Any, size: int) -> None:
        """Callback from BCC perf buffer."""
        import ctypes

        class EventData(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("ppid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32),
                ("timestamp_ns", ctypes.c_uint64),
                ("comm", ctypes.c_char * 16),
                ("syscall_nr", ctypes.c_int32),
                ("ret", ctypes.c_int64),
            ]

        event_data = ctypes.cast(data, ctypes.POINTER(EventData)).contents

        monitor_event = MonitorEvent(
            timestamp_ns=event_data.timestamp_ns,
            category=EventCategory.SYSCALL_RAW,
            source=EventSource(platform="linux", backend="ebpf", probe_name="raw_syscalls"),
            process=ProcessContext(
                pid=event_data.pid,
                tid=event_data.tid,
                ppid=event_data.ppid,
                uid=event_data.uid,
                gid=0,
                comm=event_data.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            ),
            syscall_nr=event_data.syscall_nr,
        )

        self._stats.events_received += 1
        try:
            self._event_queue.put_nowait(monitor_event)
        except asyncio.QueueFull:
            self._stats.events_dropped += 1

    def _handle_lost(self, lost_count: int) -> None:
        self._stats.events_dropped += lost_count
        log.warning("events_lost", count=lost_count)
