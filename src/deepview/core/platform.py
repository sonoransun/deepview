from __future__ import annotations
import platform as _platform
import shutil
from dataclasses import dataclass, field

from deepview.core.types import Platform, PrivilegeLevel


def detect_platform() -> Platform:
    system = _platform.system().lower()
    if system == "linux":
        return Platform.LINUX
    elif system == "darwin":
        return Platform.MACOS
    elif system == "windows":
        return Platform.WINDOWS
    raise RuntimeError(f"Unsupported platform: {system}")


@dataclass
class PlatformInfo:
    os: Platform
    arch: str
    kernel_version: str
    capabilities: set[str] = field(default_factory=set)

    @classmethod
    def detect(cls) -> PlatformInfo:
        os_platform = detect_platform()
        arch = _platform.machine()
        kernel = _platform.release()
        caps: set[str] = set()

        if os_platform == Platform.LINUX:
            if shutil.which("bpftool") or shutil.which("bpftrace") or _check_bcc():
                caps.add("ebpf")
            if _check_file_readable("/dev/mem"):
                caps.add("dev_mem")
            if _check_file_readable("/proc/kcore"):
                caps.add("proc_kcore")
            if _check_file_readable("/proc/kallsyms"):
                caps.add("kallsyms")
            if _check_file_readable("/proc/self/status"):
                caps.add("procfs")
            if _check_fanotify():
                caps.add("fanotify")
            if _check_netlink_audit():
                caps.add("audit_netlink")
            if _check_pyroute2():
                caps.add("pyroute2")
            yama = _read_file("/proc/sys/kernel/yama/ptrace_scope")
            if yama is not None:
                caps.add(f"yama_ptrace_scope={yama.strip()}")
            caps.add("ptrace")
        elif os_platform == Platform.MACOS:
            if shutil.which("dtrace"):
                caps.add("dtrace")
        elif os_platform == Platform.WINDOWS:
            caps.add("etw")

        if shutil.which("frida"):
            caps.add("frida")

        if shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat"):
            caps.add("ghidra")
        if shutil.which("hopper") or shutil.which("hopperv4"):
            caps.add("hopper")

        return cls(os=os_platform, arch=arch, kernel_version=kernel, capabilities=caps)


def _check_file_readable(path: str) -> bool:
    try:
        import os
        return os.access(path, os.R_OK)
    except Exception:
        return False


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(256)
    except OSError:
        return None


def _check_bcc() -> bool:
    try:
        import bcc  # noqa: F401
        return True
    except Exception:
        return False


def _check_fanotify() -> bool:
    import os
    # fanotify_init is syscall 300 on x86_64; simpler check is header.
    return os.path.exists("/proc/sys/fs/fanotify") or _check_file_readable(
        "/proc/sys/fs/fanotify/max_user_marks"
    )


def _check_netlink_audit() -> bool:
    try:
        import socket
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9)  # NETLINK_AUDIT
        s.close()
        return True
    except OSError:
        return False


def _check_pyroute2() -> bool:
    try:
        import pyroute2  # noqa: F401
        return True
    except Exception:
        return False


def check_privileges() -> PrivilegeLevel:
    import os
    if _platform.system() == "Windows":
        try:
            import ctypes
            return PrivilegeLevel.ROOT if ctypes.windll.shell32.IsUserAnAdmin() else PrivilegeLevel.USER
        except Exception:
            return PrivilegeLevel.USER
    else:
        if os.geteuid() == 0:
            return PrivilegeLevel.ROOT
        return PrivilegeLevel.USER
