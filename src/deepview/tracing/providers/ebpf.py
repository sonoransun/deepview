"""BCC/eBPF monitoring backend for Linux.

This backend attaches a composable **program bundle** (see
``ebpf_programs.py``) to a single perf-buffer and dispatches each raw event
to the right :mod:`deepview.tracing.events` factory based on the ``kind``
discriminator. Bundles are selected by the requested ``ProbeSpec`` set, so
callers can trade coverage for overhead.
"""
from __future__ import annotations

import asyncio
import ctypes
import socket
import struct
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

from deepview.core.exceptions import BackendNotAvailableError, ProbeAttachError
from deepview.core.logging import get_logger
from deepview.core.types import (
    EventCategory,
    EventSeverity,
    EventSource,
    ProbeType,
    ProcessContext,
)
from deepview.tracing.events import (
    MonitorEvent,
    bpf_load_event,
    credential_transition_event,
    exec_event,
    file_access_event,
    module_load_event,
    network_connect_event,
    network_listen_event,
    ptrace_event,
)
from deepview.tracing.filters import FilterExpr, FilterRule, split_for_pushdown
from deepview.tracing.providers import ebpf_programs
from deepview.tracing.providers.base import BackendStats, FilterPushDownResult, ProbeSpec

log = get_logger("tracing.providers.ebpf")


# ---------------------------------------------------------------------------
# ctypes mirror of the shared struct dv_event_t in ebpf_programs.HEADER
# ---------------------------------------------------------------------------


class _EbpfEvent(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("retval", ctypes.c_int64),
        ("syscall_nr", ctypes.c_int64),
        ("arg0", ctypes.c_uint64),
        ("arg1", ctypes.c_uint64),
        ("arg2", ctypes.c_uint64),
        ("arg3", ctypes.c_uint64),
        ("path", ctypes.c_char * 256),
        ("path2", ctypes.c_char * 256),
        ("saddr_v4", ctypes.c_uint32),
        ("daddr_v4", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("old_uid", ctypes.c_uint32),
        ("new_uid", ctypes.c_uint32),
        ("old_cap_effective", ctypes.c_uint64),
        ("new_cap_effective", ctypes.c_uint64),
        ("ptrace_request", ctypes.c_int64),
        ("ptrace_target", ctypes.c_uint32),
    ]


class EBPFBackend:
    """Linux eBPF monitoring backend using BCC.

    The backend is importable on any OS, but ``is_available`` (and therefore
    ``start``) requires BCC + Linux. The graceful fallback is important
    because the tracing manager probes every backend at module load time.
    """

    def __init__(self, ring_buffer_pages: int = 64) -> None:
        self._ring_buffer_pages = ring_buffer_pages
        self._bpf: Any = None
        self._running = False
        self._poll_thread: threading.Thread | None = None
        self._event_queue: asyncio.Queue[MonitorEvent] = asyncio.Queue(maxsize=65536)
        self._stats = BackendStats()
        self._start_time = 0.0
        self._available = False
        self._enabled_programs: set[str] = set()
        self._pushdown: list[FilterRule] = []

        try:
            from bcc import BPF  # type: ignore[import-not-found]

            self._BPF = BPF
            self._available = True
        except ImportError:
            log.debug("bcc_not_installed")

    # ------------------------------------------------------------------
    # Backend protocol
    # ------------------------------------------------------------------

    @property
    def platform(self) -> str:
        return "linux"

    @property
    def backend_name(self) -> str:
        return "ebpf"

    def is_available(self) -> bool:
        return self._available

    async def start(self, probes: list[ProbeSpec]) -> None:
        if not self._available:
            raise BackendNotAvailableError("BCC is not installed")
        try:
            self._enabled_programs = self._select_programs(probes)
            bpf_source = ebpf_programs.compose_source(self._enabled_programs)
            self._bpf = self._BPF(text=bpf_source)
            self._running = True
            self._start_time = time.time()
            self._bpf["dv_events"].open_perf_buffer(
                self._handle_event,
                page_cnt=self._ring_buffer_pages,
                lost_cb=self._handle_lost,
            )
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()
            log.info(
                "ebpf_started",
                programs=sorted(self._enabled_programs),
                pushdown_rules=len(self._pushdown),
            )
        except Exception as exc:
            raise ProbeAttachError(f"Failed to start eBPF: {exc}") from exc

    async def stop(self) -> None:
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=5.0)
        if self._bpf:
            try:
                self._bpf.cleanup()
            finally:
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
        pushed, remaining = split_for_pushdown(
            filter_expr,
            supported_fields={
                "process.pid",
                "process.uid",
                "process.comm",
                "args.path",
            },
        )
        self._pushdown = list(pushed)
        return FilterPushDownResult(pushed=pushed, remaining=remaining)

    def get_stats(self) -> BackendStats:
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return self._stats

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _select_programs(self, probes: list[ProbeSpec]) -> set[str]:
        """Select BPF programs from ``PROGRAMS`` based on requested probes."""
        if not probes:
            return {"raw_syscall"}
        selected: set[str] = set()
        for probe in probes:
            if probe.category == EventCategory.PROCESS_EXEC:
                selected.add("exec_args")
            elif probe.category == EventCategory.PROCESS:
                selected.add("exec_args")
            elif probe.category == EventCategory.MODULE_LOAD:
                selected.add("module_load")
            elif probe.category == EventCategory.CRED_TRANSITION:
                selected.add("creds")
            elif probe.category in (EventCategory.NETWORK_CONNECT, EventCategory.NETWORK_LISTEN, EventCategory.NETWORK):
                selected.add("net_flow")
            elif probe.category in (EventCategory.FILE_IO, EventCategory.FILE_ACCESS):
                selected.add("file_access")
            elif probe.category == EventCategory.PTRACE:
                selected.add("ptrace_signals")
            elif probe.category == EventCategory.BPF_LOAD:
                selected.add("bpf_load")
            elif probe.category == EventCategory.SYSCALL_RAW:
                selected.add("raw_syscall")
        if not selected:
            selected.add("raw_syscall")
        return selected

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                if not self._running:
                    break

    def _handle_event(self, cpu: int, data: Any, size: int) -> None:
        try:
            e = ctypes.cast(data, ctypes.POINTER(_EbpfEvent)).contents
        except Exception:
            return
        self._stats.events_received += 1
        monitor_event = self._decode(e)
        if monitor_event is None:
            return
        if not self._passes_user_filters(monitor_event):
            return
        try:
            self._event_queue.put_nowait(monitor_event)
        except asyncio.QueueFull:
            self._stats.events_dropped += 1

    def _passes_user_filters(self, event: MonitorEvent) -> bool:
        """Apply any pushed-down filters in user space too (defence in depth)."""
        for rule in self._pushdown:
            if rule.field_path == "process.pid" and rule.op == "eq":
                if event.process is None or event.process.pid != int(rule.value):
                    return False
            elif rule.field_path == "process.comm" and rule.op == "eq":
                if event.process is None or event.process.comm != rule.value:
                    return False
            elif rule.field_path == "args.path" and rule.op == "glob":
                import fnmatch

                path = str(event.args.get("path", ""))
                if not fnmatch.fnmatch(path, str(rule.value)):
                    return False
        return True

    def _decode(self, e: _EbpfEvent) -> MonitorEvent | None:
        """Dispatch a raw BPF event into the right typed MonitorEvent."""
        proc = ProcessContext(
            pid=int(e.pid),
            tid=int(e.tid),
            ppid=int(e.ppid),
            uid=int(e.uid),
            gid=int(e.gid),
            comm=e.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        )
        source = EventSource(platform="linux", backend="ebpf", probe_name=_kind_name(e.kind))
        ts = int(e.timestamp_ns)
        if e.kind == ebpf_programs.KIND_SYSCALL:
            return MonitorEvent(
                timestamp_ns=ts,
                category=EventCategory.SYSCALL_RAW,
                source=source,
                process=proc,
                syscall_nr=int(e.syscall_nr),
            )
        if e.kind == ebpf_programs.KIND_EXEC:
            path = e.path.decode("utf-8", errors="replace").rstrip("\x00")
            proc.exe_path = path
            return exec_event(
                process=proc,
                argv=[path] if path else [],
                interpreter="",
                source=source,
                timestamp_ns=ts,
            )
        if e.kind == ebpf_programs.KIND_MODULE_LOAD:
            return module_load_event(
                process=proc,
                module_name=e.path.decode("utf-8", errors="replace").rstrip("\x00"),
                kind="kernel_module",
                source=source,
                timestamp_ns=ts,
            )
        if e.kind == ebpf_programs.KIND_CREDS:
            return credential_transition_event(
                process=proc,
                old_uid=int(e.old_uid),
                new_uid=int(e.new_uid),
                old_caps=int(e.old_cap_effective),
                new_caps=int(e.new_cap_effective),
                source=source,
                timestamp_ns=ts,
            )
        if e.kind in (ebpf_programs.KIND_TCP_CONNECT, ebpf_programs.KIND_UDP_SENDMSG):
            return network_connect_event(
                process=proc,
                protocol="tcp" if e.kind == ebpf_programs.KIND_TCP_CONNECT else "udp",
                src_ip=_ntoa(int(e.saddr_v4)),
                src_port=socket.ntohs(int(e.sport)),
                dst_ip=_ntoa(int(e.daddr_v4)),
                dst_port=socket.ntohs(int(e.dport)),
                direction="outbound",
                source=source,
                timestamp_ns=ts,
            )
        if e.kind == ebpf_programs.KIND_INET_LISTEN:
            return network_listen_event(
                process=proc,
                protocol="tcp",
                bind_ip=_ntoa(int(e.saddr_v4)),
                bind_port=socket.ntohs(int(e.sport)),
                source=source,
                timestamp_ns=ts,
            )
        if e.kind in (ebpf_programs.KIND_FILE_OPEN, ebpf_programs.KIND_FILE_UNLINK):
            return file_access_event(
                process=proc,
                path=e.path.decode("utf-8", errors="replace").rstrip("\x00"),
                operation="open" if e.kind == ebpf_programs.KIND_FILE_OPEN else "unlink",
                source=source,
                timestamp_ns=ts,
            )
        if e.kind == ebpf_programs.KIND_PTRACE:
            return ptrace_event(
                process=proc,
                target_pid=int(e.ptrace_target),
                request="process_vm_readv" if int(e.ptrace_request) == -1 else str(int(e.ptrace_request)),
                source=source,
                timestamp_ns=ts,
            )
        if e.kind == ebpf_programs.KIND_BPF_LOAD:
            return bpf_load_event(
                process=proc,
                prog_type="unknown",
                source=source,
                timestamp_ns=ts,
            )
        return None

    def _handle_lost(self, *args: Any) -> None:
        """BCC may call this with either ``(lost,)`` or ``(cpu, lost)``."""
        if not args:
            lost = 0
        elif len(args) == 1:
            lost = int(args[0])
        else:
            lost = int(args[-1])
        self._stats.events_dropped += lost
        log.warning("events_lost", count=lost)


def _ntoa(addr: int) -> str:
    try:
        return socket.inet_ntoa(struct.pack("=I", addr & 0xFFFFFFFF))
    except Exception:
        return ""


def _kind_name(kind: int) -> str:
    return {
        ebpf_programs.KIND_SYSCALL: "raw_syscalls",
        ebpf_programs.KIND_EXEC: "sched_process_exec",
        ebpf_programs.KIND_MODULE_LOAD: "module_load",
        ebpf_programs.KIND_CREDS: "commit_creds",
        ebpf_programs.KIND_TCP_CONNECT: "tcp_v4_connect",
        ebpf_programs.KIND_UDP_SENDMSG: "udp_sendmsg",
        ebpf_programs.KIND_INET_LISTEN: "inet_listen",
        ebpf_programs.KIND_FILE_OPEN: "security_file_open",
        ebpf_programs.KIND_FILE_UNLINK: "security_inode_unlink",
        ebpf_programs.KIND_PTRACE: "ptrace",
        ebpf_programs.KIND_BPF_LOAD: "bpf_prog_load",
    }.get(kind, "unknown")
