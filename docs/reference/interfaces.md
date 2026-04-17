# Interfaces Reference

Every abstract base class that external code is expected to subclass lives in
`src/deepview/interfaces/` (or a subsystem-local `base.py`). This page
enumerates each interface, its abstract surface, the concrete subclasses
shipped by Deep View, and a minimal subclass skeleton.

All abstract methods must be implemented by a concrete subclass; properties
marked `@property @abstractmethod` are type-checked by `mypy --strict` at
subclass registration time.

## DataLayer

`src/deepview/interfaces/layer.py`. Volatility-3-style byte-addressable abstraction.
Every layer in the registry is a `DataLayer` (raw file, memory image, NAND
wrapper, decrypted container, live `/proc/[pid]/mem`, NANDFTL-composed).

```python
class DataLayer(ABC):
    @abstractmethod
    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes: ...
    @abstractmethod
    def write(self, offset: int, data: bytes) -> None: ...
    @abstractmethod
    def is_valid(self, offset: int, length: int = 1) -> bool: ...
    @abstractmethod
    def scan(self, scanner: PatternScanner,
             progress_callback: Callable | None = None) -> Iterator[ScanResult]: ...

    @property
    @abstractmethod
    def minimum_address(self) -> int: ...
    @property
    @abstractmethod
    def maximum_address(self) -> int: ...
    @property
    @abstractmethod
    def metadata(self) -> LayerMetadata: ...

    # Concrete helper
    def read_string(self, offset: int, max_length: int = 256,
                    encoding: str = "utf-8") -> str: ...
```

**Concrete subclasses:**

| Class | Module | Purpose |
|-------|--------|---------|
| `RawMemoryLayer` | `memory/formats/raw.py` | Byte-addressable raw file. |
| `LiMELayer` | `memory/formats/lime_format.py` | LiME-format memory image. |
| `ELFCoreLayer` | `memory/formats/elf_core.py` | Linux kernel ELF core dump. |
| `CrashDumpLayer` | `memory/formats/crashdump.py` | Windows minidump/crashdump. |
| `HibernationLayer` | `memory/formats/hibernation.py` | `hiberfil.sys` decoder. |
| `VirtualLayer` | `memory/translation/virtual_layer.py` | Page-table-translated virtual view. |
| `LiveProcessLayer` | `inspect/live_layer.py` | `/proc/[pid]/mem` wrapped as a layer. |
| `DecryptedVolumeLayer` | `storage/containers/layer.py` | AES-XTS read-through over a unlocked container. |
| `RawNANDLayer` / `ECCDecodedLayer` / `FTLTranslatedLayer` | `storage/layers/*` | NAND wrapping stack. |

**Subclass skeleton:**

```python
from deepview.interfaces.layer import DataLayer
from deepview.core.types import LayerMetadata

class FakeLayer(DataLayer):
    def __init__(self, data: bytes) -> None:
        self._data = data
    def read(self, offset, length, *, pad=False):
        out = self._data[offset:offset + length]
        if pad and len(out) < length:
            out += b"\x00" * (length - len(out))
        return out
    def write(self, offset, data):
        raise NotImplementedError
    def is_valid(self, offset, length=1):
        return 0 <= offset and offset + length <= len(self._data)
    def scan(self, scanner, progress_callback=None):
        yield from scanner.scan(self._data, offset=0)
    @property
    def minimum_address(self): return 0
    @property
    def maximum_address(self): return max(0, len(self._data) - 1)
    @property
    def metadata(self): return LayerMetadata(name="fake")
```

## Filesystem

`src/deepview/interfaces/filesystem.py`. POSIX-ish adapter over a backing
`DataLayer`. `FSEntry` is a frozen dataclass of the usual MAC-times plus
`is_dir`, `is_symlink`, `is_deleted`, `target`, and an `extra` mapping.

```python
class Filesystem(ABC):
    fs_name: str = ""
    block_size: int = 0
    def __init__(self, layer: DataLayer, offset: int = 0) -> None: ...

    @classmethod
    @abstractmethod
    def probe(cls, layer: DataLayer, offset: int = 0) -> bool: ...
    @abstractmethod
    def list(self, path: str = "/", *, recursive: bool = False,
             include_deleted: bool = False) -> Iterator[FSEntry]: ...
    @abstractmethod
    def stat(self, path: str) -> FSEntry: ...
    @abstractmethod
    def open(self, path: str) -> DataLayer: ...
    @abstractmethod
    def read(self, path: str, offset: int = 0, length: int = -1) -> bytes: ...

    def find(self, pattern: str, *, regex: bool = False) -> Iterator[FSEntry]: ...
    def unallocated(self) -> Iterator[FSEntry]: ...
    def close(self) -> None: ...
```

**Concrete adapters** (all in `storage/filesystems/`):

| Adapter | Module | Backend |
|---------|--------|---------|
| `EXTFilesystem` | `ext.py` | `pyfsext` (ext2/3/4 native). |
| `NTFSFilesystem` | `ntfs_native.py` | `pyfsntfs` (USN + ADS). |
| `APFSFilesystem` | `apfs.py` | `pyfsapfs`. |
| `XFSFilesystem` | `xfs.py` | `pyfsxfs`. |
| `BtrfsFilesystem` | `btrfs.py` | `pyfsbtrfs`. |
| `F2FSFilesystem` | `f2fs.py` | `pyfsf2fs`. |
| `HFSFilesystem` | `hfs.py` | `pyfshfs`. |
| `FATFilesystem` | `fat_native.py` | Stdlib (FAT12/16/32). |
| `TSKFilesystem` | `tsk.py` | `pytsk3` fallback (ext/FAT/NTFS/HFS+/ISO). |
| `ZFSFilesystem` | `zfs.py` | Best-effort ZFS reader. |

## FTLTranslator

`src/deepview/interfaces/ftl.py`. Flash Translation Layer: maps logical LBAs
to physical NAND pages.

```python
class FTLTranslator(ABC):
    name: str = ""

    @classmethod
    @abstractmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometryProto) -> bool: ...
    @abstractmethod
    def build_map(self, layer: DataLayer,
                  geometry: NANDGeometryProto) -> Iterator[LBAMapping]: ...
    @abstractmethod
    def translate(self, lba: int) -> LBAMapping | None: ...
    def logical_size(self) -> int: ...
```

**Concrete translators** (all in `storage/ftl/`):

| Class | Module | Notes |
|-------|--------|-------|
| `UBITranslator` | `ubi.py` | UBI volume walker. |
| `JFFS2Translator` | `jffs2.py` | JFFS2 node-chain replayer. |
| `MTDPassthroughTranslator` | `mtd.py` | Identity mapping for raw MTD dumps. |
| `BadBlockRemapTranslator` | `badblock.py` | Walks bad-block marker tables. |
| `EMMCHintTranslator` | `emmc_hints.py` | eMMC hint-driven translator. |
| `UFSTranslator` | `ufs.py` | UFS logical map. |

## ECCDecoder

`src/deepview/interfaces/ecc.py`. Stateless forward-error-correcting decoder.

```python
class ECCDecoder(ABC):
    name: str = ""
    data_chunk: int = 0
    ecc_bytes: int = 0

    @abstractmethod
    def decode(self, data: bytes, ecc: bytes) -> ECCResult: ...
    def encode(self, data: bytes) -> bytes: ...
```

`ECCResult` carries `data`, `errors_corrected`, `uncorrectable`.

**Concrete decoders:**

| Class | Module | Backend |
|-------|--------|---------|
| `HammingDecoder` | `storage/ecc/hamming.py` | Pure-Python SEC-DED. |
| `BCHDecoder` | `storage/ecc/bch.py` | `galois` accelerator. |
| `ReedSolomonDecoder` | `storage/ecc/reed_solomon.py` | `reedsolo` accelerator. |

## Scanner (PatternScanner)

`src/deepview/interfaces/scanner.py`. Abstract byte-pattern / YARA scanner.

```python
class PatternScanner(ABC):
    @abstractmethod
    def scan(self, data: bytes, offset: int = 0) -> Iterator[ScanResult]: ...
    @abstractmethod
    def scan_layer(self, layer: DataLayer,
                   progress_callback: Callable | None = None) -> Iterator[ScanResult]: ...
    @abstractmethod
    def load_rules(self, path: Path) -> None: ...
    @property
    @abstractmethod
    def rule_count(self) -> int: ...
```

**Concrete subclasses:**

| Class | Module | Notes |
|-------|--------|-------|
| `YaraScanner` | `scanning/yara.py` | `yara-python` backed. |
| `StringCarver` | `scanning/strings.py` | Multi-encoding string carver. |
| `IoCEngine` | `scanning/ioc.py` | Indicator-of-compromise matcher. |

## MemoryAcquisitionProvider

`src/deepview/interfaces/acquisition.py`. Provider contract for live memory
capture.

```python
class MemoryAcquisitionProvider(ABC):
    @abstractmethod
    def acquire(self, target: AcquisitionTarget, output: Path,
                fmt: DumpFormat = DumpFormat.RAW) -> AcquisitionResult: ...
    @abstractmethod
    def is_available(self) -> bool: ...
    @abstractmethod
    def supported_platforms(self) -> list[Platform]: ...
    @abstractmethod
    def requires_privileges(self) -> PrivilegeLevel: ...
    @classmethod
    @abstractmethod
    def provider_name(cls) -> str: ...
```

**Concrete providers:**

| Class | Module | Target OS |
|-------|--------|-----------|
| `LiMEProvider` | `memory/acquisition/lime.py` | Linux (LKM). |
| `AVMLProvider` | `memory/acquisition/avml.py` | Linux (Microsoft AVML). |
| `WinPmemProvider` | `memory/acquisition/winpmem.py` | Windows. |
| `OSXPmemProvider` | `memory/acquisition/osxpmem.py` | macOS. |
| `LiveProvider` | `memory/acquisition/live.py` | Generic `/dev/mem` or `/proc/kcore`. |

## RemoteAcquisitionProvider

`src/deepview/memory/acquisition/remote/base.py`. Extends
`MemoryAcquisitionProvider` with a `RemoteEndpoint` + progress-publishing helper.

```python
class RemoteAcquisitionProvider(MemoryAcquisitionProvider):
    def __init__(self, endpoint: RemoteEndpoint, *,
                 context: AnalysisContext) -> None: ...
    @abstractmethod
    def transport_name(self) -> str: ...
    def _emit_progress(self, bytes_done: int, bytes_total: int, stage: str) -> None: ...
```

`RemoteEndpoint` is a frozen dataclass holding host, transport literal,
optional `port`/`username`/`identity_file`/`password_env`/`known_hosts`/`tls_ca`,
a `require_tls` default of `True`, and a free-form `extra` mapping. Credentials
are never stored inline.

**Concrete providers** (all in `memory/acquisition/remote/`):

| Class | Module | Transport |
|-------|--------|-----------|
| `SSHDDProvider` | `ssh_dd.py` | `ssh host 'sudo dd if=/dev/mem'`. |
| `TCPStreamProvider` | `tcp_stream.py` | TCP listener + external streamer. |
| `NetworkAgentProvider` | `network_agent.py` | gRPC pull from `deepview-agent`. |
| `LIMERemoteProvider` | `lime_remote.py` | Remote LiME acquisition. |
| `IPMIProvider` | `ipmi.py` | IPMI OOB via `python-ipmi`. |
| `IntelAMTProvider` | `intel_amt.py` | Intel AMT OOB. |
| `DMAThunderboltProvider` | `dma_thunderbolt.py` | Thunderbolt DMA. |
| `DMAPCIeProvider` | `dma_pcie.py` | PCIe DMA. |
| `DMAFirewireProvider` | `dma_firewire.py` | Firewire DMA via `forensic1394`. |

## OffloadBackend

`src/deepview/offload/backends/base.py`. Scheduler contract for CPU-bound
work such as PBKDF2 / Argon2 / bulk SHA-512.

```python
@dataclass(frozen=True, slots=True)
class BackendStats:
    name: str
    available: bool
    capabilities: set[str] = field(default_factory=set)
    in_flight: int = 0

class OffloadBackend(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...
    @abstractmethod
    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]: ...
    @abstractmethod
    def capabilities(self) -> set[str]: ...
    @abstractmethod
    def is_available(self) -> bool: ...
    @abstractmethod
    def shutdown(self, wait: bool = True) -> None: ...

    def in_flight(self) -> int: ...
    def stats(self) -> BackendStats: ...
```

**Concrete backends** (all in `offload/backends/`):

| Class | Module | Notes |
|-------|--------|-------|
| `ThreadPoolBackend` | `thread.py` | Stdlib `ThreadPoolExecutor`. |
| `ProcessPoolBackend` | `process.py` | Stdlib `ProcessPoolExecutor`. |
| `CUDABackend` | `gpu_cuda.py` | `pycuda` accelerator. Opt-in via `config.offload.gpu_enabled`. |
| `OpenCLBackend` | `gpu_opencl.py` | `pyopencl` accelerator. |
| `RemoteWorkerBackend` | `remote.py` | Submit work to a remote deepview-agent. |

## Unlocker / KeySource

`src/deepview/storage/containers/unlock.py`. Encrypted-container ABCs.

```python
class KeySource(ABC):
    @abstractmethod
    async def derive(self, engine: OffloadEngine,
                     header: ContainerHeader) -> bytes: ...

@dataclass(frozen=True)
class MasterKey(KeySource):
    key: bytes
    async def derive(self, ...): return self.key

@dataclass(frozen=True)
class Passphrase(KeySource):
    passphrase: str
    async def derive(self, ...): ...  # routes KDF job to OffloadEngine

@dataclass(frozen=True)
class Keyfile(KeySource):
    path: Path
    async def derive(self, ...): return sha256(path.read_bytes()).digest()

class Unlocker(ABC):
    format_name: ClassVar[str] = ""
    @abstractmethod
    def detect(self, layer: DataLayer, offset: int = 0) -> ContainerHeader | None: ...
    @abstractmethod
    async def unlock(self, layer, header, source, *,
                     try_hidden: bool = False) -> DecryptedVolumeLayer: ...
```

`ContainerHeader` is a frozen dataclass: `format`, `cipher`, `sector_size`,
`data_offset`, `data_length`, `kdf`, `kdf_params`, `raw`.

**Concrete unlockers:**

| Class | Module | Format |
|-------|--------|--------|
| `LUKSUnlocker` | `storage/containers/luks.py` | LUKS1 / LUKS2 (aes-xts-plain64). |
| `BitLockerUnlocker` | `storage/containers/bitlocker.py` | Windows BitLocker. |
| `FileVault2Unlocker` | `storage/containers/filevault2.py` | macOS FileVault 2. |
| `_VeraCryptBase` (→ `VeraCryptUnlocker`, `TrueCryptUnlocker`) | `storage/containers/veracrypt.py` | VeraCrypt (VERA) / TrueCrypt (TRUE) containers. |

`UnlockOrchestrator` (same module) keeps the registry, drives
`auto_unlock(layer, passphrases=..., keyfiles=..., scan_keys=...,
try_hidden=...)`, and publishes
[`ContainerUnlockStartedEvent` / `ContainerUnlockProgressEvent` /
`ContainerUnlockedEvent` / `ContainerUnlockFailedEvent`](events.md#container-unlock-events).

## Tracer (SystemTracer)

`src/deepview/interfaces/tracer.py`. Kernel / user-space tracing backend.

```python
class SystemTracer(ABC):
    @abstractmethod
    def attach(self, probe: ProbeDefinition) -> ProbeHandle: ...
    @abstractmethod
    def detach(self, handle: ProbeHandle) -> None: ...
    @abstractmethod
    def start(self) -> None: ...
    @abstractmethod
    def stop(self) -> None: ...
    @abstractmethod
    def poll_events(self, timeout: float | None = None) -> Iterator[TraceEvent]: ...
    @abstractmethod
    def supported_probe_types(self) -> list[ProbeType]: ...
```

`ProbeDefinition` holds `probe_type`, `target`, `filter_expr`, `fields`,
`entry`, `exit`. `TraceEvent` carries the usual `category` / `severity` /
`process` / `syscall_name` / `args` / `return_value` / `latency_ns`.

**Concrete backends** (all in `tracing/providers/`):

| Class | Module | Platform |
|-------|--------|----------|
| `EBPFBackend` | `ebpf.py` | Linux (BCC + perf buffer). |
| `DTraceBackend` | `dtrace.py` | macOS / illumos. |
| `ETWBackend` | `etw.py` | Windows. |

## Instrumentor

`src/deepview/interfaces/instrumentor.py`. Frida-style instrumentation.

```python
class InstrumentationSession(ABC):
    @abstractmethod
    def inject_hook(self, hook: HookDefinition) -> HookHandle: ...
    @abstractmethod
    def remove_hook(self, handle: HookHandle) -> None: ...
    @abstractmethod
    def read_memory(self, address: int, size: int) -> bytes: ...
    @abstractmethod
    def write_memory(self, address: int, data: bytes) -> None: ...
    @abstractmethod
    def enumerate_modules(self) -> list[ModuleInfo]: ...
    @abstractmethod
    def on_message(self, callback: Callable) -> None: ...
    @property
    @abstractmethod
    def pid(self) -> int: ...

class Instrumentor(ABC):
    @abstractmethod
    def attach(self, target: int | str) -> InstrumentationSession: ...
    @abstractmethod
    def spawn(self, program: Path,
              args: list[str] | None = None) -> InstrumentationSession: ...
    @abstractmethod
    def detach(self, session: InstrumentationSession) -> None: ...
    @abstractmethod
    def is_available(self) -> bool: ...
```

`HookDefinition` carries `hook_id`, `module`, `function`, `address`,
`on_enter`, `on_leave`, `arg_types`, `capture_backtrace`, `capture_args`,
`capture_retval`, `enabled`.

**Concrete implementations:**

| Class | Module | Backend |
|-------|--------|---------|
| `FridaInstrumentor` | `instrumentation/frida_engine.py` | `frida` optional dep. |
| `StaticBinaryPatcher` | `instrumentation/binary/patcher.py` | `lief` + `capstone` static-reassembly pipeline. |

## VMConnector

`src/deepview/interfaces/vm_connector.py`. Hypervisor / VM operations.

```python
class VMConnector(ABC):
    @abstractmethod
    def connect(self, uri: str = "") -> None: ...
    @abstractmethod
    def disconnect(self) -> None: ...
    @abstractmethod
    def list_vms(self) -> list[VMInfo]: ...
    @abstractmethod
    def snapshot(self, vm_id: str, name: str) -> SnapshotInfo: ...
    @abstractmethod
    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> None: ...
    @abstractmethod
    def extract_memory(self, vm_id: str, output: Path) -> Path: ...
    @abstractmethod
    def is_available(self) -> bool: ...
    @classmethod
    @abstractmethod
    def connector_name(cls) -> str: ...
```

**Concrete connectors** (all in `vm/connectors/`):

| Class | Module | Hypervisor |
|-------|--------|------------|
| `QEMUKVMConnector` | `qemu_kvm.py` | libvirt / QEMU / KVM. |
| `VirtualBoxConnector` | `virtualbox.py` | VirtualBox via `vboxmanage`. |
| `VMWareConnector` | `vmware.py` | VMware via `vmrun`. |

## Disassembler

`src/deepview/interfaces/disassembler.py`. Disassembly + RE backend.

```python
class DisassemblyEngine(ABC):
    @abstractmethod
    def open_binary(self, path: Path) -> DisassemblySession: ...
    @abstractmethod
    def is_available(self) -> bool: ...
    @classmethod
    @abstractmethod
    def engine_name(cls) -> str: ...
    @classmethod
    @abstractmethod
    def supported_capabilities(cls) -> set[str]: ...

class DisassemblySession(ABC):
    @abstractmethod
    def disassemble(self, address: int, count: int = 20) -> list[dict[str, Any]]: ...
    @abstractmethod
    def disassemble_function(self, name_or_address: str | int) -> list[dict[str, Any]]: ...
    @abstractmethod
    def decompile(self, name_or_address: str | int) -> str: ...
    @abstractmethod
    def functions(self) -> list[dict[str, Any]]: ...
    @abstractmethod
    def xrefs_to(self, address: int) -> list[dict[str, Any]]: ...
    @abstractmethod
    def xrefs_from(self, address: int) -> list[dict[str, Any]]: ...
    @abstractmethod
    def cfg(self, name_or_address: str | int) -> dict[str, Any]: ...
    @abstractmethod
    def strings(self, min_length: int = 4) -> list[dict[str, Any]]: ...
    @abstractmethod
    def close(self) -> None: ...
    @property
    @abstractmethod
    def binary_info(self) -> dict[str, Any]: ...
```

Standard `supported_capabilities()` strings: `disassemble`, `decompile`,
`cfg`, `xrefs`, `functions`, `strings`, `data_types`, `signatures`.

**Concrete engines** (all in `disassembly/engines/`):

| Class | Module | Capabilities |
|-------|--------|--------------|
| `CapstoneEngine` | `capstone_engine.py` | `disassemble`, `functions`, `strings`. |
| `GhidraEngine` | `ghidra.py` | All capabilities via `pyhidra`. |
| `HopperEngine` | `hopper.py` | All capabilities via Hopper CLI. |

## DeepViewPlugin

`src/deepview/interfaces/plugin.py`. Base for every analysis plugin.

```python
class RequirementType(str, Enum):
    LAYER = "layer"
    CONFIG = "config"
    PLUGIN_OUTPUT = "plugin_output"
    PRIVILEGE = "privilege"

@dataclass
class Requirement:
    name: str
    description: str
    required: bool = True
    requirement_type: RequirementType = RequirementType.CONFIG
    default: Any = None

@dataclass
class PluginResult:
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

class DeepViewPlugin(ABC):
    def __init__(self, context: AnalysisContext,
                 config: dict | None = None) -> None:
        self.context = context
        self.config = config or {}

    @classmethod
    @abstractmethod
    def get_requirements(cls) -> list[Requirement]: ...
    @abstractmethod
    def run(self) -> PluginResult: ...

    @classmethod
    def get_metadata(cls) -> PluginMetadata: ...
    @classmethod
    def supported_platforms(cls) -> list[Platform]:  # defaults to all three
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]
```

**Concrete subclasses:** see [plugins.md](plugins.md) for the full catalog.

## ResultRenderer

`src/deepview/interfaces/renderer.py`. Output formatter.

```python
class ResultRenderer(ABC):
    @abstractmethod
    def render(self, result: PluginResult, output: IO | None = None) -> str: ...
    @abstractmethod
    def format_name(self) -> str: ...
```

**Concrete renderers** (all in `cli/formatters/`): `TableRenderer`,
`JsonRenderer`, `CsvRenderer`, `TimelineRenderer`, `LiveRenderer` (streaming
Rich `Live` renderer used by `trace` / `monitor`).

## AnalysisEngine

`src/deepview/interfaces/analysis.py`. Memory-forensics engine wrapper.

```python
class AnalysisEngine(ABC):
    @abstractmethod
    def open_image(self, path: Path) -> DataLayer: ...
    @abstractmethod
    def run_plugin(self, plugin_name: str, layer: DataLayer, **kwargs) -> Any: ...
    @abstractmethod
    def list_plugins(self) -> list[str]: ...
    @abstractmethod
    def is_available(self) -> bool: ...
    @classmethod
    @abstractmethod
    def engine_name(cls) -> str: ...
```

**Concrete engines:**

| Class | Module | Backend |
|-------|--------|---------|
| `VolatilityEngine` | `memory/analysis/volatility.py` | `volatility3` (used as a library). |
| `MemProcFSEngine` | `memory/analysis/memprocfs.py` | `memprocfs` binary / Python API. |

## Cross-references

- Events published by each subsystem: [events.md](events.md).
- CLI commands driving each interface: [cli.md](cli.md).
- Config sections per subsystem: [config.md](config.md).
- Plugin catalog + metadata: [plugins.md](plugins.md).
