"""Trace event data models."""
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
#
# Backends (macOS Endpoint Security, the eBPF decoders, ETW) translate their
# native records into these semantic ``MonitorEvent`` shapes. Keeping the
# construction here means every backend tags, categorises, and scores events
# identically, and the timeline / correlation layers can rely on stable
# ``category`` + ``args`` keys.
# ---------------------------------------------------------------------------


def exec_event(
    *,
    process: ProcessContext,
    argv: list[str] | tuple[str, ...] = (),
    envp: dict[str, str] | None = None,
    interpreter: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A process image was executed (``execve`` / ES exec)."""
    return MonitorEvent(
        category=EventCategory.PROCESS_EXEC,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"argv": list(argv), "envp": dict(envp or {}), "interpreter": interpreter},
        tags=["exec"],
    )


def fork_event(
    *,
    process: ProcessContext,
    child_pid: int,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A process forked/cloned a child."""
    return MonitorEvent(
        category=EventCategory.PROCESS_FORK,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"child_pid": int(child_pid)},
        tags=["fork"],
    )


def file_access_event(
    *,
    process: ProcessContext,
    path: str,
    operation: str = "",
    new_path: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A file was opened/renamed/unlinked."""
    return MonitorEvent(
        category=EventCategory.FILE_ACCESS,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"path": path, "operation": operation, "new_path": new_path},
        tags=["file"],
    )


def ptrace_event(
    *,
    process: ProcessContext,
    target_pid: int,
    request: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A ptrace/debug attach — a classic code-injection precursor (T1055.008)."""
    return MonitorEvent(
        category=EventCategory.PTRACE,
        severity=EventSeverity.WARNING,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"target_pid": int(target_pid), "request": request},
        tags=["ptrace", "injection_suspect"],
    )


def memory_map_event(
    *,
    process: ProcessContext,
    addr: int,
    length: int,
    prot: str = "",
    flags: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A memory region was mapped/protected; W+X is flagged as suspicious."""
    tags = ["mmap"]
    severity = EventSeverity.INFO
    upper = prot.upper()
    if "W" in upper and "X" in upper:
        tags.append("wx")
        severity = EventSeverity.WARNING
    return MonitorEvent(
        category=EventCategory.MEMORY_MAP,
        severity=severity,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"addr": int(addr), "length": int(length), "prot": prot, "flags": flags},
        tags=tags,
    )


def module_load_event(
    *,
    process: ProcessContext,
    module_name: str,
    module_path: str = "",
    kind: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A kernel module / kext / shared object was loaded."""
    return MonitorEvent(
        category=EventCategory.MODULE_LOAD,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"module_name": module_name, "module_path": module_path, "kind": kind},
        tags=["module"],
    )


def network_connect_event(
    *,
    process: ProcessContext,
    protocol: str,
    src_ip: str = "",
    src_port: int = 0,
    dst_ip: str = "",
    dst_port: int = 0,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """An outbound connection was established."""
    return MonitorEvent(
        category=EventCategory.NETWORK,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": int(src_port),
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
        },
        tags=[protocol, "connect"],
    )


def network_listen_event(
    *,
    process: ProcessContext,
    protocol: str,
    bind_ip: str = "",
    bind_port: int = 0,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A socket began listening (possible backdoor/bind shell)."""
    return MonitorEvent(
        category=EventCategory.NETWORK,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"protocol": protocol, "bind_ip": bind_ip, "bind_port": int(bind_port)},
        tags=[protocol, "listen"],
    )


def credential_transition_event(
    *,
    process: ProcessContext,
    old_uid: int,
    new_uid: int,
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A UID transition; escalation to root is flagged as a warning (T1548)."""
    escalated = int(new_uid) == 0 and int(old_uid) != 0
    return MonitorEvent(
        category=EventCategory.CREDENTIAL,
        severity=EventSeverity.WARNING if escalated else EventSeverity.INFO,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"old_uid": int(old_uid), "new_uid": int(new_uid)},
        tags=["credential"],
    )


def bpf_load_event(
    *,
    process: ProcessContext,
    prog_type: str = "",
    source: EventSource | None = None,
    timestamp_ns: int = 0,
) -> MonitorEvent:
    """A BPF program was loaded (eBPF rootkits / tracing tools; T1547)."""
    return MonitorEvent(
        category=EventCategory.BPF_LOAD,
        process=process,
        source=source,
        timestamp_ns=timestamp_ns,
        args={"prog_type": prog_type},
        tags=["bpf"],
    )
