"""Audit netlink (``NETLINK_AUDIT``) reader, stdlib-only.

The Linux kernel multicasts audit messages on a netlink socket that
any process with ``CAP_AUDIT_READ`` can subscribe to. This module is
an intentionally small client that follows the kernel's audit record
format just enough to reconstruct ``MonitorEvent``s. It deliberately
does not reimplement ``auditd`` — we just want to consume existing
records while a normal auditd is (or is not) running.

If the kernel does not expose NETLINK_AUDIT or the caller lacks the
capability, :meth:`AuditSource.start` raises
:class:`BackendNotAvailableError` and the caller can fall back.
"""
from __future__ import annotations

import select
import socket
import struct
import threading
import time

from deepview.core.exceptions import BackendNotAvailableError
from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import TraceEventBus

log = get_logger("tracing.linux.audit")


NETLINK_AUDIT = 9
AUDIT_GET = 1000
AUDIT_SET = 1001
AUDIT_NLGRP_READLOG = 1


class AuditSource:
    """Consume audit records from the kernel's audit netlink multicast."""

    def __init__(self, bus: TraceEventBus) -> None:
        self._bus = bus
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
        except OSError as e:
            raise BackendNotAvailableError(f"NETLINK_AUDIT unavailable: {e}") from e
        try:
            sock.bind((0, 1 << (AUDIT_NLGRP_READLOG - 1)))
        except OSError as e:
            sock.close()
            raise BackendNotAvailableError(f"audit multicast bind failed: {e}") from e
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="audit-source")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while self._running:
            try:
                ready, _, _ = select.select([sock], [], [], 0.5)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                data, _addr = sock.recvfrom(65536)
            except OSError:
                return
            self._process(data)

    def _process(self, data: bytes) -> None:
        # nlmsghdr: u32 len, u16 type, u16 flags, u32 seq, u32 pid
        offset = 0
        while offset + 16 <= len(data):
            nlmsg_len, nlmsg_type, _flags, _seq, _pid = struct.unpack_from(
                "=IHHII", data, offset
            )
            payload_end = offset + nlmsg_len
            if nlmsg_len < 16 or payload_end > len(data):
                break
            payload = data[offset + 16 : payload_end]
            text = payload.decode("utf-8", errors="replace").rstrip("\x00").strip()
            if text:
                self._publish(nlmsg_type, text)
            offset = (payload_end + 3) & ~3  # align to 4

    def _publish(self, msg_type: int, text: str) -> None:
        fields = _parse_audit_record(text)
        pid = int(fields.get("pid", "0") or "0") if fields.get("pid", "").isdigit() else 0
        uid = int(fields.get("uid", "0") or "0") if fields.get("uid", "").isdigit() else 0
        comm = fields.get("comm", "").strip('"')
        event = MonitorEvent(
            timestamp_ns=time.monotonic_ns(),
            wall_clock_ns=time.time_ns(),
            category=EventCategory.PROCESS,
            severity=EventSeverity.INFO,
            source=EventSource(platform="linux", backend="audit", probe_name=f"audit_{msg_type}"),
            process=ProcessContext(pid=pid, tid=pid, ppid=0, uid=uid, gid=0, comm=comm),
            syscall_name=fields.get("syscall", "") or "audit",
            args=dict(fields),
        )
        self._bus.publish_sync(event)


def _parse_audit_record(text: str) -> dict[str, str]:
    """Parse an audit record into key=value pairs.

    Audit records look like ``type=SYSCALL msg=audit(...): arch=c000003e
    syscall=59 success=yes ...``. We split on whitespace but respect
    quoted values. The record header (``type=.. msg=audit(..)``) is
    preserved so the caller still gets the record type in ``type`` and
    the raw timestamp in ``msg``.
    """
    out: dict[str, str] = {}
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        eq = text.find("=", i)
        if eq < 0:
            break
        key = text[i:eq].strip()
        i = eq + 1
        if i < len(text) and text[i] == '"':
            end = text.find('"', i + 1)
            if end < 0:
                break
            value = text[i + 1 : end]
            i = end + 1
        else:
            end = i
            while end < len(text) and not text[end].isspace():
                end += 1
            value = text[i:end]
            i = end
        out[key] = value
    return out
