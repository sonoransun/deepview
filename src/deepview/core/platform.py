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
            if shutil.which("bpftool") or shutil.which("bpftrace"):
                caps.add("ebpf")
            if _check_file_readable("/dev/mem"):
                caps.add("dev_mem")
            if _check_file_readable("/proc/kcore"):
                caps.add("proc_kcore")
            caps.add("ptrace")
        elif os_platform == Platform.MACOS:
            if shutil.which("dtrace"):
                caps.add("dtrace")
        elif os_platform == Platform.WINDOWS:
            caps.add("etw")

        if shutil.which("frida"):
            caps.add("frida")

        return cls(os=os_platform, arch=arch, kernel_version=kernel, capabilities=caps)


def _check_file_readable(path: str) -> bool:
    try:
        import os
        return os.access(path, os.R_OK)
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
