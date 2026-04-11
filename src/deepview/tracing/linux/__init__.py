"""Linux-specific tracing sources, helpers, and tables.

This package sits alongside ``deepview.tracing.providers`` and contains
Linux-only code paths that can be imported on any platform as long as
module-level imports stay stdlib-only. Heavy or OS-gated helpers live in
submodules and lazy-import their third-party dependencies on first use.
"""
from __future__ import annotations

from deepview.tracing.linux import procfs
from deepview.tracing.linux.syscalls import (
    SYSCALLS_X86_64,
    FILESYSTEM_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    syscall_name,
    syscall_nr,
)

__all__ = [
    "procfs",
    "SYSCALLS_X86_64",
    "FILESYSTEM_SYSCALLS",
    "NETWORK_SYSCALLS",
    "PROCESS_SYSCALLS",
    "syscall_name",
    "syscall_nr",
]
