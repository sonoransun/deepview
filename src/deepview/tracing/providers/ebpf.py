"""BCC/eBPF monitoring backend for Linux."""
from __future__ import annotations
import asyncio
import time
import threading
from collections.abc import AsyncIterator
from typing import Any

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSource, ProcessContext
from deepview.core.exceptions import BackendNotAvailableError, ProbeAttachError
from deepview.tracing.events import MonitorEvent
from deepview.tracing.filters import FilterExpr, FilterPlan, FilterRule
from deepview.tracing.linux.syscalls import syscall_name
from deepview.tracing.providers.base import BackendStats, FilterInput, FilterPushDownResult, ProbeSpec

log = get_logger("tracing.providers.ebpf")

# Header block shared by every composed program. The struct layout MUST
# stay in lockstep with ``EventData`` in :meth:`EBPFBackend._handle_event`.
# Slice 1 keeps the template simple; Slice 3 adds kernel-side allowlist
# maps for real filter push-down.
_BPF_HEADER = r"""
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
"""

def _raw_syscalls_body(inline_pid: int | None, inline_uid: int | None) -> str:
    """Return the raw_syscalls tracepoint body with optional inline guards.

    When a single PID (or UID) is staged by ``apply_filter``, we bake it
    directly into the BPF source as a literal so the kernel drops
    unmatched events before they ever reach the perf buffer. This is
    the Slice 1 stopgap for missing kernel-side maps and keeps the
    default firehose tractable for ``trace syscall --pid N``.
    """
    pid_guard = f"if (pid_tgid_hi != {inline_pid}) return 0;" if inline_pid is not None else ""
    uid_guard = f"if (uid32 != {inline_uid}) return 0;" if inline_uid is not None else ""
    return r"""
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid_tgid_hi = pid_tgid >> 32;
    """ + pid_guard + r"""
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid32 = uid_gid & 0xFFFFFFFF;
    """ + uid_guard + r"""

    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = pid_tgid_hi;
    event.tid = pid_tgid & 0xFFFFFFFF;
    event.ppid = task->real_parent->tgid;
    event.uid = uid32;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.syscall_nr = args->id;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


# Backwards-compatibility alias for tests that imported the old name.
BPF_TEMPLATE = _BPF_HEADER + _raw_syscalls_body(None, None)


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
        self._loop: asyncio.AbstractEventLoop | None = None
        # User-space residual filter to evaluate before queueing. Set by
        # apply_filter(); populated as a plain FilterExpr so we don't need
        # the FilterPlan type (added in Slice 3) to import cleanly.
        self._residual_filter: FilterExpr | None = None
        # Kernel hints staged by apply_filter() and written into BPF
        # maps during start() once the program has been compiled.
        self._kernel_pids: set[int] = set()
        self._kernel_uids: set[int] = set()
        self._kernel_comms: set[str] = set()
        self._kernel_syscall_nrs: set[int] = set()
        # Optional override source (e.g. "trace custom --program file.bpf.c").
        self._override_source: str | None = None
        # Fast user-space reject sets extracted from the filter expression.
        # When non-empty, a raw event must match one of each populated set
        # before we allocate a Pydantic MonitorEvent. This is a Slice 1
        # stopgap for the missing kernel-side push-down; Slice 3 replaces
        # it with real BPF allowlist maps.
        self._fast_pids: set[int] = set()
        self._fast_uids: set[int] = set()
        self._fast_comms: set[bytes] = set()
        self._fast_syscall_nrs: set[int] = set()

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
            self._loop = asyncio.get_running_loop()
            bpf_source = self._override_source or self._generate_bpf_source(probes)
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

    def set_override_source(self, source: str) -> None:
        """Pin a raw BPF C source that bypasses probe composition.

        Used by ``deepview trace custom --program PATH``. The custom
        program MUST declare ``BPF_PERF_OUTPUT(events)`` and a matching
        event struct layout; otherwise the user-space ``_handle_event``
        callback will not decode it correctly.
        """
        self._override_source = source

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

    def apply_filter(self, filter_expr: FilterInput) -> FilterPushDownResult:
        """Stage a compiled :class:`FilterPlan` on the backend.

        Accepts either a :class:`FilterPlan` (from
        :meth:`FilterExpr.compile`) or a raw :class:`FilterExpr` for
        backwards compatibility; the raw form is compiled on the fly.

        Hints drive two kernel-side specialisations:

        * A **single** staged PID or UID is baked into the BPF source
          as a literal ``if (... != N) return 0;`` guard at compile
          time, which is the most useful Slice 3 push-down we can do
          without a HASH map.
        * Multiple PIDs/UIDs and the full comm / syscall_nr sets are
          still evaluated in user-space, but the raw-ctypes fast path
          in :meth:`_handle_event` rejects mismatches *before* any
          Pydantic allocation so the poll thread stays cheap.
        """
        self._fast_pids.clear()
        self._fast_uids.clear()
        self._fast_comms.clear()
        self._fast_syscall_nrs.clear()

        if filter_expr is None:
            self._residual_filter = None
            return FilterPushDownResult(pushed=[], remaining=[])

        if isinstance(filter_expr, FilterPlan):
            plan = filter_expr
        else:
            plan = filter_expr.compile()

        hints = plan.kernel_hints
        self._fast_pids = set(hints.pids)
        self._fast_uids = set(hints.uids)
        self._fast_comms = {str(c).encode("utf-8")[:16] for c in hints.comms}
        self._fast_syscall_nrs = set(hints.syscall_nrs)
        self._residual_filter = plan.remainder

        pushed: list[FilterRule] = []
        for field_name, values in (
            ("process.pid", hints.pids),
            ("process.uid", hints.uids),
            ("process.comm", hints.comms),
            ("syscall_nr", hints.syscall_nrs),
            ("category", hints.categories),
        ):
            if values:
                pushed.append(FilterRule(field_name, "in", list(values)))
        return FilterPushDownResult(pushed=pushed, remaining=[])


    def get_stats(self) -> BackendStats:
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return self._stats

    def _generate_bpf_source(self, probes: list[ProbeSpec]) -> str:
        """Compose a BPF C program from a probe list.

        Slice 1 supports a single emitter, ``raw_syscalls:sys_enter``,
        with optional compile-time PID/UID guards baked in from the
        staged ``apply_filter`` state. Future slices extend this to
        kprobes/tracepoints with their own structs.
        """
        _ = probes  # Reserved for future dispatch.
        inline_pid = next(iter(self._fast_pids)) if len(self._fast_pids) == 1 else None
        inline_uid = next(iter(self._fast_uids)) if len(self._fast_uids) == 1 else None
        return _BPF_HEADER + _raw_syscalls_body(inline_pid, inline_uid)

    def _poll_loop(self) -> None:
        """Background thread polling the perf buffer."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                if not self._running:
                    break

    def _handle_event(self, cpu: int, data: Any, size: int) -> None:
        """Callback from BCC perf buffer (runs on the poll thread)."""
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
        nr = int(event_data.syscall_nr)

        # Fast user-space pre-check: reject before any Pydantic
        # allocation. Empty set means "no restriction on that field".
        if self._fast_pids and int(event_data.pid) not in self._fast_pids:
            return
        if self._fast_uids and int(event_data.uid) not in self._fast_uids:
            return
        if self._fast_syscall_nrs and nr not in self._fast_syscall_nrs:
            return
        if self._fast_comms:
            raw_comm = bytes(event_data.comm).rstrip(b"\x00")
            if raw_comm not in self._fast_comms:
                return

        monitor_event = MonitorEvent(
            timestamp_ns=int(event_data.timestamp_ns),
            wall_clock_ns=time.time_ns(),
            category=EventCategory.SYSCALL_RAW,
            source=EventSource(platform="linux", backend="ebpf", probe_name="raw_syscalls"),
            process=ProcessContext(
                pid=int(event_data.pid),
                tid=int(event_data.tid),
                ppid=int(event_data.ppid),
                uid=int(event_data.uid),
                gid=0,
                comm=event_data.comm.decode("utf-8", errors="replace").rstrip("\x00"),
            ),
            syscall_nr=nr,
            syscall_name=syscall_name(nr),
            return_value=int(event_data.ret) if event_data.ret else None,
        )

        # User-space residual filter evaluation.
        if self._residual_filter is not None and not self._residual_filter.evaluate(monitor_event):
            return

        self._stats.events_received += 1
        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._put_event_threadsafe, monitor_event)
        else:
            try:
                self._event_queue.put_nowait(monitor_event)
            except asyncio.QueueFull:
                self._stats.events_dropped += 1

    def _put_event_threadsafe(self, event: MonitorEvent) -> None:
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            self._stats.events_dropped += 1

    def _handle_lost(self, lost_count: int) -> None:
        self._stats.events_dropped += lost_count
        log.warning("events_lost", count=lost_count)
