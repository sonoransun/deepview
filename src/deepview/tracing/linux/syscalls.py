"""x86_64 Linux syscall tables and category groupings.

This is intentionally a static table rather than a parse of
``/usr/include/asm-generic/unistd.h`` so that code paths that only need
name resolution work without any compile-time dependency. Numbers are
from Linux 6.x ``unistd_64.h``; the list covers the syscalls that the
tracing, classification, and inspection subsystems care about. Unknown
numbers resolve to ``"syscall_<nr>"``.
"""
from __future__ import annotations


SYSCALLS_X86_64: dict[int, str] = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    32: "dup",
    33: "dup2",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    72: "fcntl",
    74: "fsync",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    101: "ptrace",
    102: "getuid",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    157: "prctl",
    158: "arch_prctl",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    175: "init_module",
    176: "delete_module",
    186: "gettid",
    200: "tkill",
    202: "futex",
    217: "getdents64",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    272: "unshare",
    288: "accept4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    302: "prlimit64",
    304: "open_by_handle_at",
    310: "process_vm_readv",
    311: "process_vm_writev",
    316: "renameat2",
    319: "memfd_create",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    332: "statx",
    435: "clone3",
    436: "close_range",
    437: "openat2",
    438: "pidfd_getfd",
    439: "faccessat2",
    440: "process_madvise",
    441: "epoll_pwait2",
    442: "mount_setattr",
    449: "futex_waitv",
    450: "set_mempolicy_home_node",
}


_NAME_TO_NR: dict[str, int] = {v: k for k, v in SYSCALLS_X86_64.items()}


FILESYSTEM_SYSCALLS: frozenset[str] = frozenset({
    "open", "openat", "openat2", "open_by_handle_at", "creat",
    "read", "pread64", "readv", "preadv2",
    "write", "pwrite64", "writev", "pwritev2",
    "close", "close_range",
    "stat", "fstat", "lstat", "statx", "access", "faccessat", "faccessat2",
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "mkdir", "mkdirat", "rmdir", "link", "linkat", "symlink", "symlinkat",
    "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "lchown", "fchownat",
    "readlink", "readlinkat",
    "mount", "umount2",
    "memfd_create",
})

NETWORK_SYSCALLS: frozenset[str] = frozenset({
    "socket", "socketpair",
    "bind", "listen", "accept", "accept4",
    "connect",
    "sendto", "sendmsg", "recvfrom", "recvmsg",
    "shutdown",
    "getsockname", "getpeername",
    "setsockopt", "getsockopt",
})

PROCESS_SYSCALLS: frozenset[str] = frozenset({
    "fork", "vfork", "clone", "clone3",
    "execve", "execveat",
    "exit", "exit_group",
    "wait4",
    "kill", "tkill", "tgkill",
    "ptrace",
    "prctl", "arch_prctl",
    "setuid", "setgid",
    "init_module", "delete_module",
    "unshare",
})


def syscall_name(nr: int) -> str:
    """Resolve a syscall number to a name, or ``syscall_<nr>`` if unknown."""
    return SYSCALLS_X86_64.get(nr, f"syscall_{nr}")


def syscall_nr(name: str) -> int | None:
    """Resolve a syscall name to its x86_64 number, or ``None`` if unknown."""
    return _NAME_TO_NR.get(name)


def resolve_nrs(names: frozenset[str] | set[str] | list[str]) -> list[int]:
    """Resolve a collection of names to a deduplicated list of numbers."""
    out: set[int] = set()
    for n in names:
        nr = _NAME_TO_NR.get(n)
        if nr is not None:
            out.add(nr)
    return sorted(out)
