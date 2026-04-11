from __future__ import annotations

import enum
from pathlib import Path

from pydantic import BaseModel, Field


class Platform(str, enum.Enum):
    LINUX = "linux"
    MACOS = "darwin"
    WINDOWS = "windows"


class PrivilegeLevel(str, enum.Enum):
    USER = "user"
    ELEVATED = "elevated"
    ROOT = "root"
    KERNEL = "kernel"


class DumpFormat(str, enum.Enum):
    RAW = "raw"
    LIME = "lime"
    ELF_CORE = "elf_core"
    CRASHDUMP = "crashdump"
    PADDED = "padded"
    NAND_RAW = "nand_raw"
    EMMC_RAW = "emmc_raw"
    JTAG_RAM = "jtag_ram"
    SPI_FLASH = "spi_flash"
    GPU_VRAM = "gpu_vram"


class ProbeType(str, enum.Enum):
    SYSCALL = "syscall"
    KPROBE = "kprobe"
    UPROBE = "uprobe"
    TRACEPOINT = "tracepoint"
    USDT = "usdt"
    HARDWARE_TRACE = "hardware_trace"
    CORESIGHT = "coresight"


class EventCategory(str, enum.Enum):
    PROCESS = "process"
    PROCESS_EXEC = "process_exec"
    PROCESS_FORK = "process_fork"
    PROCESS_EXIT = "process_exit"
    FILE_IO = "file_io"
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    MEMORY = "memory"
    MEMORY_MAP = "memory_map"
    MODULE = "module"
    MODULE_LOAD = "module_load"
    REGISTRY = "registry"
    SIGNAL = "signal"
    SYSCALL_RAW = "syscall_raw"
    CRED_TRANSITION = "cred_transition"
    PTRACE = "ptrace"
    BPF_LOAD = "bpf_load"
    CONTAINER = "container"
    DNS = "dns"
    TLS = "tls"


class EventSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class PluginCategory(str, enum.Enum):
    MEMORY_ANALYSIS = "memory_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    MALWARE_DETECTION = "malware_detection"
    TIMELINE = "timeline"
    CREDENTIALS = "credentials"
    ROOTKIT_DETECTION = "rootkit_detection"
    NETWORK_FORENSICS = "network_forensics"
    ARTIFACT_RECOVERY = "artifact_recovery"
    DIFFERENTIAL = "differential"
    CUSTOM = "custom"


class DisassemblyBackend(str, enum.Enum):
    GHIDRA = "ghidra"
    HOPPER = "hopper"
    CAPSTONE = "capstone"
    AUTO = "auto"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ModuleInfo(BaseModel):
    """A loaded binary module (shared lib, DLL, kext, kernel module)."""

    name: str
    base_address: int = 0
    size: int = 0
    path: str = ""


class FdInfo(BaseModel):
    """Open file descriptor / handle on a process."""

    fd: int
    kind: str = ""  # "file", "socket", "pipe", "anon_inode", "eventfd", ...
    target: str = ""  # path, "socket:[inode]", ...
    flags: int = 0


class ThreadInfo(BaseModel):
    """A single thread within a process."""

    tid: int
    start_address: int = 0
    state: str = ""
    name: str = ""


class NamespaceSet(BaseModel):
    """Linux namespace identifiers (inode numbers)."""

    mnt: int | None = None
    pid: int | None = None
    net: int | None = None
    user: int | None = None
    uts: int | None = None
    ipc: int | None = None
    cgroup: int | None = None
    time: int | None = None


class SigningInfo(BaseModel):
    """Executable signing metadata (Authenticode / codesign / IMA)."""

    signed: bool = False
    signer: str = ""
    subject: str = ""
    team_id: str = ""  # macOS codesign team identifier
    signing_chain: list[str] = Field(default_factory=list)
    verified: bool = False


class ProcessContext(BaseModel):
    """Rich process identity + forensic state.

    Only ``pid`` / ``tid`` / ``comm`` are effectively mandatory; every other
    field has a sensible default so call-sites can populate incrementally as
    richer data becomes available.
    """

    pid: int
    tid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""
    exe_path: str = ""
    cgroup: str = ""

    # Expanded identity
    cmdline: list[str] = Field(default_factory=list)
    cwd: str = ""
    env: dict[str, str] = Field(default_factory=dict)

    # Executable integrity
    exe_hash_sha256: str = ""
    exe_signing: SigningInfo | None = None

    # Runtime state
    loaded_modules: list[ModuleInfo] = Field(default_factory=list)
    open_fds: list[FdInfo] = Field(default_factory=list)
    threads: list[ThreadInfo] = Field(default_factory=list)

    # Session / TTY
    tty: str = ""
    session_id: int | None = None
    auid: int | None = None  # Linux audit UID (survives setuid)

    # Containment / sandbox
    namespaces: NamespaceSet | None = None
    cgroup_path: str = ""
    container_id: str = ""
    k8s_pod: str = ""
    k8s_namespace: str = ""

    # Privilege context (Linux)
    capabilities_effective: int = 0
    capabilities_permitted: int = 0
    selinux_context: str = ""
    apparmor_profile: str = ""

    # Privilege context (Windows)
    integrity_level: str = ""
    token_privileges: list[str] = Field(default_factory=list)

    # Ancestry
    parent_chain: list[int] = Field(default_factory=list)  # pids from pid up to init

    def stable_key(self, boot_ns: int | None = None) -> str:
        """Return a stable entity key ``process:<pid>@<boot_ns>``.

        ``boot_ns`` is an optional boot-time anchor so that PID reuse across
        reboots still produces distinct entities. If omitted the bare pid is
        used.
        """
        if boot_ns is None:
            return f"process:{self.pid}"
        return f"process:{self.pid}@{boot_ns}"


class EventSource(BaseModel):
    platform: str
    backend: str
    probe_name: str


class LayerMetadata(BaseModel):
    name: str
    os: str = ""
    arch: str = ""
    minimum_address: int = 0
    maximum_address: int = 0


class AcquisitionTarget(BaseModel):
    hostname: str = "localhost"
    pid: int | None = None
    method: str = "auto"


class AcquisitionResult(BaseModel):
    success: bool
    output_path: Path | None = None
    format: DumpFormat
    size_bytes: int = 0
    duration_seconds: float = 0.0
    hash_sha256: str = ""


class PluginMetadata(BaseModel):
    name: str
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    category: PluginCategory = PluginCategory.CUSTOM
    tags: list[str] = Field(default_factory=list)
    platforms: list[Platform] = Field(
        default_factory=lambda: [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]
    )


class VMInfo(BaseModel):
    vm_id: str
    name: str
    state: str
    hypervisor: str
    memory_mb: int = 0


class SnapshotInfo(BaseModel):
    snapshot_id: str
    vm_id: str
    name: str
    timestamp: str = ""
    has_memory: bool = False


class ScanResult(BaseModel):
    offset: int
    length: int
    rule_name: str = ""
    data: bytes = b""
    metadata: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Disassembly / reverse-engineering models
# ---------------------------------------------------------------------------


class DisassembledInstruction(BaseModel):
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int
    comment: str = ""


class DecompiledFunction(BaseModel):
    name: str
    address: int
    source: str
    language: str = "c"


class FunctionRecord(BaseModel):
    name: str
    address: int
    size: int = 0
    calling_convention: str = ""
    return_type: str = ""
    parameters: list[str] = Field(default_factory=list)


class CrossReference(BaseModel):
    from_address: int
    to_address: int
    ref_type: str  # "call", "data", "jump", "offset"
    from_function: str = ""
    to_function: str = ""


class CFGBlock(BaseModel):
    address: int
    size: int
    instructions: list[DisassembledInstruction] = Field(default_factory=list)
    successors: list[int] = Field(default_factory=list)
    predecessors: list[int] = Field(default_factory=list)


class ControlFlowGraph(BaseModel):
    function_name: str
    function_address: int
    blocks: list[CFGBlock] = Field(default_factory=list)
    edge_count: int = 0


class StringRecord(BaseModel):
    address: int
    value: str
    encoding: str = "utf-8"
    section: str = ""
    xref_count: int = 0
