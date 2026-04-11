"""Trace event data models.

``MonitorEvent`` is the universal wire type every tracing backend emits. The
``*_event`` helpers below are factories that build a ``MonitorEvent`` with the
right ``category``, ``args``, and ``tags`` for a specific semantic event. They
are preferred over constructing ``MonitorEvent`` directly because they keep
the field conventions consistent across backends and consumers.
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Any
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext


@dataclass(slots=True)
class MonitorEvent:
    """Universal event type for all monitoring backends."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp_ns: int = 0
    wall_clock_ns: int = 0
    category: EventCategory = EventCategory.SYSCALL_RAW
    severity: EventSeverity = EventSeverity.INFO
    source: EventSource | None = None
    process: ProcessContext | None = None
    syscall_name: str = ""
    syscall_nr: int = -1
    args: dict[str, Any] = field(default_factory=dict)
    return_value: int | None = None
    latency_ns: int = 0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Enriched event factories
# ---------------------------------------------------------------------------


def exec_event(
    *,
    process: ProcessContext,
    argv: list[str],
    envp: dict[str, str] | None = None,
    interpreter: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
    wall_clock_ns: int = 0,
) -> MonitorEvent:
    """``execve`` success event with the full argv / envp."""
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        wall_clock_ns=wall_clock_ns,
        category=EventCategory.PROCESS_EXEC,
        source=source,
        process=process,
        syscall_name="execve",
        args={
            "argv": list(argv),
            "envp": dict(envp or {}),
            "interpreter": interpreter,
        },
        tags=["exec"],
    )


def fork_event(
    *,
    process: ProcessContext,
    child_pid: int,
    child_tid: int = 0,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.PROCESS_FORK,
        source=source,
        process=process,
        syscall_name="clone",
        args={"child_pid": child_pid, "child_tid": child_tid},
        tags=["fork"],
    )


def exit_event(
    *,
    process: ProcessContext,
    exit_code: int,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.PROCESS_EXIT,
        source=source,
        process=process,
        syscall_name="exit",
        args={"exit_code": exit_code},
        tags=["exit"],
    )


def file_access_event(
    *,
    process: ProcessContext,
    path: str,
    operation: str,  # "open", "read", "write", "unlink", "rename"
    flags: int = 0,
    mode: int = 0,
    new_path: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.FILE_ACCESS,
        source=source,
        process=process,
        syscall_name=operation,
        args={
            "path": path,
            "flags": flags,
            "mode": mode,
            "new_path": new_path,
        },
        tags=["file", operation],
    )


def module_load_event(
    *,
    process: ProcessContext,
    module_name: str,
    module_path: str = "",
    kind: str = "kernel_module",  # kernel_module | shared_lib | ebpf_program | driver | kext
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.MODULE_LOAD,
        source=source,
        process=process,
        syscall_name="module_load",
        args={"name": module_name, "path": module_path, "kind": kind},
        tags=["module", kind],
    )


def credential_transition_event(
    *,
    process: ProcessContext,
    old_uid: int,
    new_uid: int,
    old_caps: int = 0,
    new_caps: int = 0,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    severity = (
        EventSeverity.WARNING if new_uid == 0 and old_uid != 0 else EventSeverity.INFO
    )
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.CRED_TRANSITION,
        severity=severity,
        source=source,
        process=process,
        syscall_name="commit_creds",
        args={
            "old_uid": old_uid,
            "new_uid": new_uid,
            "old_caps": old_caps,
            "new_caps": new_caps,
        },
        tags=["cred", "privilege"],
    )


def network_connect_event(
    *,
    process: ProcessContext,
    protocol: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    direction: str = "outbound",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.NETWORK_CONNECT,
        source=source,
        process=process,
        syscall_name="connect",
        args={
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "direction": direction,
        },
        tags=["net", direction, protocol],
    )


def network_listen_event(
    *,
    process: ProcessContext,
    protocol: str,
    bind_ip: str,
    bind_port: int,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.NETWORK_LISTEN,
        source=source,
        process=process,
        syscall_name="listen",
        args={"protocol": protocol, "bind_ip": bind_ip, "bind_port": bind_port},
        tags=["net", "listen", protocol],
    )


def ptrace_event(
    *,
    process: ProcessContext,
    target_pid: int,
    request: str,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.PTRACE,
        severity=EventSeverity.WARNING,
        source=source,
        process=process,
        syscall_name="ptrace",
        args={"target_pid": target_pid, "request": request},
        tags=["ptrace", "injection_suspect"],
    )


def bpf_load_event(
    *,
    process: ProcessContext,
    prog_type: str,
    prog_name: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.BPF_LOAD,
        source=source,
        process=process,
        syscall_name="bpf",
        args={"prog_type": prog_type, "prog_name": prog_name},
        tags=["bpf", "module"],
    )


def memory_map_event(
    *,
    process: ProcessContext,
    addr: int,
    length: int,
    prot: str,
    flags: str = "",
    fd: int = -1,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=timestamp_ns,
        category=EventCategory.MEMORY_MAP,
        source=source,
        process=process,
        syscall_name="mmap",
        args={
            "addr": addr,
            "length": length,
            "prot": prot,
            "flags": flags,
            "fd": fd,
        },
        tags=["mmap", "memory"],
    )
