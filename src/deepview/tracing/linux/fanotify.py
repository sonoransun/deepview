"""Minimal libc-based fanotify source.

``fanotify`` gives a process with ``CAP_SYS_ADMIN`` a file descriptor
that streams filesystem access events across an entire mount. This
module does not try to be a complete fanotify client — it covers the
small forensics-oriented subset: open/access notifications with the
originating PID and path. Events flow into a :class:`TraceEventBus`.

If libc can't be located or the kernel does not support fanotify,
``FanotifySource.start`` raises :class:`BackendNotAvailableError` and
the caller (typically the monitor CLI) prints a helpful message and
skips this source.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import threading
import time
from typing import Any

from deepview.core.exceptions import BackendNotAvailableError
from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.tracing.events import MonitorEvent
from deepview.tracing.stream import TraceEventBus

log = get_logger("tracing.linux.fanotify")


# fanotify_init flags
FAN_CLOEXEC = 0x1
FAN_NONBLOCK = 0x2
FAN_CLASS_NOTIF = 0x0
# fanotify_mark flags
FAN_MARK_ADD = 0x1
FAN_MARK_MOUNT = 0x10
FAN_MARK_FILESYSTEM = 0x100
# Event mask bits
FAN_ACCESS = 0x1
FAN_MODIFY = 0x2
FAN_CLOSE_WRITE = 0x8
FAN_CLOSE_NOWRITE = 0x10
FAN_OPEN = 0x20
FAN_OPEN_EXEC = 0x1000
FAN_EVENT_ON_CHILD = 0x08000000

# fanotify_event_metadata layout (see uapi/linux/fanotify.h).
_FAN_EVENT_FMT = "BBHIqi"
_FAN_EVENT_SIZE = struct.calcsize(_FAN_EVENT_FMT)


def _libc() -> Any:
    name = ctypes.util.find_library("c")
    if not name:
        raise BackendNotAvailableError("libc not found for fanotify")
    return ctypes.CDLL(name, use_errno=True)


class FanotifySource:
    """fanotify-backed filesystem activity source."""

    def __init__(
        self,
        bus: TraceEventBus,
        *,
        mark_paths: list[str] | None = None,
        event_mask: int = FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE_WRITE,
    ) -> None:
        self._bus = bus
        self._mark_paths = mark_paths or ["/"]
        self._event_mask = event_mask
        self._fd: int = -1
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        libc = _libc()
        fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY)
        if fd < 0:
            err = ctypes.get_errno()
            raise BackendNotAvailableError(f"fanotify_init failed: errno={err}")
        self._fd = fd
        for path in self._mark_paths:
            rc = libc.fanotify_mark(
                fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                ctypes.c_uint64(self._event_mask),
                -100,  # AT_FDCWD
                path.encode("utf-8"),
            )
            if rc < 0:
                err = ctypes.get_errno()
                log.warning("fanotify_mark_failed", path=path, errno=err)
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="fanotify-source")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        import select

        while self._running:
            if self._fd < 0:
                return
            try:
                ready, _, _ = select.select([self._fd], [], [], 0.5)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                buf = os.read(self._fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                return
            self._process(buf)

    def _process(self, buf: bytes) -> None:
        offset = 0
        while offset + _FAN_EVENT_SIZE <= len(buf):
            _version, _reserved, metadata_len, mask, fd, pid = struct.unpack_from(
                _FAN_EVENT_FMT, buf, offset
            )
            path = ""
            if fd >= 0:
                try:
                    path = os.readlink(f"/proc/self/fd/{fd}")
                except OSError:
                    path = ""
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            comm = ""
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                    comm = f.read().strip()
            except OSError:
                pass
            event = MonitorEvent(
                timestamp_ns=time.monotonic_ns(),
                wall_clock_ns=time.time_ns(),
                category=EventCategory.FILE_IO,
                severity=EventSeverity.INFO,
                source=EventSource(platform="linux", backend="fanotify", probe_name="fanotify"),
                process=ProcessContext(pid=pid, tid=pid, ppid=0, uid=0, gid=0, comm=comm),
                syscall_name=_mask_to_name(mask),
                args={"path": path, "mask": hex(mask)},
            )
            self._bus.publish_sync(event)
            offset += metadata_len if metadata_len else _FAN_EVENT_SIZE


def _mask_to_name(mask: int) -> str:
    if mask & FAN_OPEN_EXEC:
        return "open_exec"
    if mask & FAN_OPEN:
        return "open"
    if mask & FAN_CLOSE_WRITE:
        return "close_write"
    if mask & FAN_CLOSE_NOWRITE:
        return "close_nowrite"
    if mask & FAN_MODIFY:
        return "modify"
    if mask & FAN_ACCESS:
        return "access"
    return f"fanotify_{mask:x}"
