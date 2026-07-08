from __future__ import annotations

import enum
from pathlib import Path
from typing import Any

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
    HIBERFIL = "hiberfil"
    MINIDUMP_FULL = "minidump_full"
    VMWARE_VMEM = "vmware_vmem"
    VIRTUALBOX_SAV = "virtualbox_sav"
    HYPERV_VMRS = "hyperv_vmrs"


class ProbeType(str, enum.Enum):
    SYSCALL = "syscall"
    KPROBE = "kprobe"
    UPROBE = "uprobe"
    TRACEPOINT = "tracepoint"
    USDT = "usdt"
    HARDWARE_TRACE = "hardware_trace"
    CORESIGHT = "coresight"
    FANOTIFY = "fanotify"
    AUDIT = "audit"
    PROCFS = "procfs"


class EventCategory(str, enum.Enum):
    PROCESS = "process"
    FILE_IO = "file_io"
    NETWORK = "network"
    MEMORY = "memory"
    MODULE = "module"
    REGISTRY = "registry"
    SIGNAL = "signal"
    SYSCALL_RAW = "syscall_raw"
    KERNEL_MODULE = "kernel_module"
    NAMESPACE = "namespace"
    AUDIT = "audit"
    CLASSIFICATION = "classification"
    # Enriched semantic categories emitted by the event factories
    # (see ``deepview.tracing.events``) and consumed by the ES backend,
    # eBPF decoders, and the timeline trace-events source.
    PROCESS_EXEC = "process_exec"
    PROCESS_FORK = "process_fork"
    FILE_ACCESS = "file_access"
    PTRACE = "ptrace"
    MEMORY_MAP = "memory_map"
    MODULE_LOAD = "module_load"
    BPF_LOAD = "bpf_load"
    CREDENTIAL = "credential"


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


class ThreadInfo(BaseModel):
    """A thread within a process (start address powers RWX-injection heuristics)."""
    tid: int = 0
    start_address: int = 0
    stack_base: int = 0
    state: str = ""


class SigningInfo(BaseModel):
    """Code-signing provenance for an executable (macOS ES / PE Authenticode)."""
    signed: bool = False
    team_id: str = ""
    signer: str = ""
    verified: bool = False


class NamespaceSet(BaseModel):
    """Linux namespace inode numbers for a process (from ``/proc/<pid>/ns``)."""
    mnt: int | None = None
    pid: int | None = None
    net: int | None = None
    user: int | None = None
    uts: int | None = None
    ipc: int | None = None
    cgroup: int | None = None
    time: int | None = None


class ProcessContext(BaseModel):
    pid: int
    tid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""
    exe_path: str = ""
    cgroup: str = ""
    cgroup_path: str = ""
    cmdline: list[str] = Field(default_factory=list)
    cwd: str = ""
    exe_hash_sha256: str = ""
    exe_signing: SigningInfo | None = None
    auid: int | None = None
    tty: str = ""
    integrity_level: str = ""
    selinux_context: str = ""
    container_id: str = ""
    k8s_pod: str = ""
    k8s_namespace: str = ""
    namespaces: NamespaceSet | None = None
    threads: list[ThreadInfo] = Field(default_factory=list)
    loaded_modules: list[Any] = Field(default_factory=list)

    def stable_key(self, boot_ns: int | None = None) -> str:
        """Correlation-graph identity for this process.

        The optional *boot_ns* (process start time in boot-relative ns)
        disambiguates recycled PIDs across a capture.
        """
        base = f"process:{self.pid}"
        return f"{base}@{boot_ns}" if boot_ns is not None else base


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
    hash_sha256: str = ""  # digest value (algorithm named below)
    # Provenance / chain-of-custody
    algorithm: str = "sha256"
    acquired_at: str = ""  # UTC ISO-8601
    tool_version: str = ""
    # Completeness / integrity
    truncated: bool = False
    bytes_expected: int = 0  # 0 = unknown
    read_error: str = ""
    manifest_path: Path | None = None


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


class ModuleInfo(BaseModel):
    name: str
    base_address: int
    size: int
    path: str = ""


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
