# Deep View

**Cross-platform computer system forensics and runtime analysis toolkit**

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-green)
![Version](https://img.shields.io/badge/version-0.1.0-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Overview

Deep View is a unified forensic analysis framework that brings together memory forensics, live system monitoring, virtual machine introspection, binary instrumentation, and hardware-assisted extraction into a single, extensible toolkit. It is designed for incident responders, malware analysts, threat hunters, and security researchers who need to investigate compromised systems, analyze suspicious binaries, and correlate evidence across multiple data sources --- from user-space process memory down to physical DRAM, SPI flash, and GPU VRAM.

The toolkit operates across Linux, macOS, and Windows, abstracting platform-specific mechanisms behind common interfaces. Memory dumps acquired with LiME, AVML, WinPmem, or OSXPmem are analyzed through dual engines --- Volatility 3 for its deep plugin ecosystem and MemProcFS for high-performance filesystem-style access. Hardware-assisted acquisition via DMA (PCILeech over PCIe/Thunderbolt), cold boot DRAM remanence capture, and JTAG/chip-off extraction extends reach to non-cooperative, powered-off, and embedded targets. Live systems are observed through eBPF programs on Linux, DTrace probes on macOS, and ETW sessions on Windows, all feeding a unified event stream. Intel Processor Trace and ARM CoreSight provide instruction-level recording invisible to malware. Application behavior is captured through Frida-based dynamic instrumentation or static binary reassembly with embedded monitoring hooks.

Deep View includes independent page table reconstruction (CR3 → PML4 → PT walk on raw physical memory), multi-encoding string carving with entropy filtering, TCP/IP stack reconstruction from kernel structures, and volatile artifact recovery (shell command history, clipboard, registry hives, environment variables). Detection modules automatically identify anti-forensics techniques (DKOM, SSDT hooks, inline hooks, PatchGuard bypasses, hypervisor rootkits, bootkits), process injection (12 MITRE T1055 sub-techniques), and encryption key material (AES, RSA, BitLocker, TLS session keys). Firmware-level analysis covers UEFI rootkit detection and SPI flash integrity verification. Findings are mapped to the MITRE ATT&CK framework and exported as STIX 2.1 intelligence objects for integration with SOC workflows.

---

## Architecture

```mermaid
graph TB
    CLI["CLI Interface<br/>(Click + Rich)"]:::core
    CTX["Analysis Context"]:::core
    EB["Event Bus<br/>(Pub/Sub)"]:::core

    subgraph Core["Core Framework"]
        CTX
        EB
        CFG["Config<br/>(Pydantic)"]:::core
        PLT["Platform<br/>Detection"]:::core
        PR["Plugin Registry<br/>(3-tier discovery)"]:::core
    end

    subgraph Memory["Memory Forensics"]
        MM["Memory Manager"]:::analysis
        ACQ["Acquisition<br/>LiME | AVML | WinPmem | OSXPmem"]:::source
        FMT["Format Parsers<br/>Raw | LiME | ELF Core | Crashdump"]:::analysis
        VOL["Volatility 3<br/>Engine"]:::analysis
        MPF["MemProcFS<br/>Engine"]:::analysis
        SYM["Symbol Manager<br/>(dwarf2json)"]:::analysis
        PTW["Page Table Walker<br/>(CR3 → PML4 → PT)"]:::analysis
        VAL["Virtual Address Layer"]:::analysis
    end

    subgraph Hardware["Hardware-Assisted Extraction"]
        DMA["DMA Acquisition<br/>(PCILeech, Thunderbolt, FireWire)"]:::hardware
        CB["Cold Boot<br/>(DRAM remanence)"]:::hardware
        JTAG["JTAG / Chip-Off / ISP<br/>(mobile, embedded, IoT)"]:::hardware
        SPI["SPI Flash<br/>(Bus Pirate, Dediprog)"]:::hardware
        GPU["GPU Memory<br/>(CUDA, OpenCL)"]:::hardware
    end

    subgraph Tracing["System Tracing"]
        TM["Trace Manager"]:::instrument
        BPF["eBPF/BCC<br/>(Linux)"]:::instrument
        DT["DTrace<br/>(macOS)"]:::instrument
        ETW["ETW<br/>(Windows)"]:::instrument
        IPT["Intel PT<br/>(branch trace)"]:::instrument
        CS["ARM CoreSight"]:::instrument
        TEB["Trace Event Bus<br/>(async queues)"]:::instrument
    end

    subgraph Instrument["Instrumentation"]
        IM["Instrumentation Manager"]:::instrument
        FE["Frida Engine<br/>(dynamic hooks)"]:::instrument
        BA["Binary Analyzer<br/>(LIEF)"]:::instrument
        RE["Reassembler<br/>(trampoline injection)"]:::instrument
    end

    subgraph VM["VM Introspection"]
        VMM["VM Manager"]:::analysis
        QEMU["QEMU/KVM<br/>(libvirt)"]:::analysis
        VBOX["VirtualBox<br/>(vboxmanage)"]:::analysis
        VMW["VMware<br/>(vmrun)"]:::analysis
        VMI["LibVMI / DRAKVUF<br/>(live introspection)"]:::analysis
    end

    subgraph Detection["Detection & Scanning"]
        AF["Anti-Forensics<br/>(DKOM, hooks, PatchGuard)"]:::detect
        INJ["Injection Detection<br/>(T1055)"]:::detect
        EK["Key Scanner<br/>(AES, RSA, BitLocker, TLS)"]:::detect
        AD["Anomaly Detection<br/>(heuristic + ML)"]:::detect
        RK["Rootkit Detection<br/>(hypervisor, bootkit)"]:::detect
        YS["YARA Scanner"]:::detect
        SC["String Carver<br/>(multi-encoding)"]:::detect
        IOC["IoC Engine"]:::detect
    end

    subgraph Artifacts["Volatile Artifact Recovery"]
        TCP["TCP/IP Stack<br/>Reconstruction"]:::detect
        CMD["Command History<br/>(cmd, PS, bash)"]:::detect
        FW["Firmware / UEFI<br/>Analysis"]:::detect
    end

    subgraph Reporting["Reporting & Export"]
        RE2["Report Engine<br/>(HTML, Markdown, JSON)"]:::report
        TL["Timeline Builder"]:::report
        STIX["STIX 2.1 Export"]:::report
        ATT["ATT&CK Mapper<br/>(Navigator layers)"]:::report
    end

    CLI --> CTX
    CTX --> MM
    CTX --> TM
    CTX --> IM
    CTX --> VMM
    CTX --> PR

    MM --> ACQ
    MM --> FMT
    MM --> VOL
    MM --> MPF
    MM --> SYM
    MM --> PTW
    PTW --> VAL

    Hardware --> MM
    DMA --> MM
    CB --> MM
    JTAG --> MM
    SPI --> FW
    GPU --> MM

    TM --> BPF
    TM --> DT
    TM --> ETW
    TM --> IPT
    TM --> CS
    TM --> TEB

    IM --> FE
    IM --> BA
    IM --> RE

    VMM --> QEMU
    VMM --> VBOX
    VMM --> VMW
    VMM --> VMI

    MM --> YS
    MM --> SC
    MM --> AF
    MM --> INJ
    MM --> EK
    MM --> RK
    MM --> TCP
    MM --> CMD

    AF --> STIX
    INJ --> ATT
    RK --> ATT
    TL --> RE2

    classDef core fill:#868e96,stroke:#495057,color:#fff
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef hardware fill:#ff8787,stroke:#e03131,color:#1a1a2e
    classDef instrument fill:#3bc9db,stroke:#1098ad,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
```

### Data Flow

```mermaid
flowchart LR
    subgraph Sources["Evidence Sources"]
        LIVE["Live System"]:::source
        DUMP["Memory Dump"]:::source
        VMSNAP["VM Snapshot"]:::source
        BIN["Suspect Binary"]:::source
        HW["Hardware Target<br/>(PCIe, JTAG, DIMM)"]:::hardware
        FW["Firmware<br/>(SPI Flash)"]:::hardware
        GPUD["GPU Device"]:::hardware
    end

    subgraph Acquire["Acquisition"]
        A1["LiME / AVML /<br/>WinPmem / OSXPmem"]:::source
        A2["VM Extract<br/>(virsh, vboxmanage, vmrun)"]:::source
        A3["DMA / Cold Boot /<br/>JTAG / Chip-Off"]:::hardware
        A4["SPI Read<br/>(flashrom, CHIPSEC)"]:::hardware
        A5["GPU Dump<br/>(CUDA, OpenCL)"]:::hardware
    end

    subgraph Analyze["Analysis Layer"]
        DL["DataLayer<br/>(abstract memory source)"]:::analysis
        PTW["Page Table Walker<br/>(virtual addr translation)"]:::analysis
        V3["Volatility 3"]:::analysis
        MFS["MemProcFS"]:::analysis
    end

    subgraph Detect["Detection"]
        YARA["YARA Rules<br/>(malware, creds, exploits)"]:::detect
        STRCAR["String Carver<br/>(multi-encoding + entropy)"]:::detect
        DET["Detection Modules<br/>(DKOM, injection, keys,<br/>rootkits, bootkits)"]:::detect
        ARTIF["Artifact Recovery<br/>(TCP stack, commands,<br/>clipboard, registry)"]:::detect
        SCORE["Anomaly Scoring"]:::detect
    end

    subgraph Report["Output"]
        HTML["HTML Report"]:::report
        STIXO["STIX 2.1 Bundle"]:::report
        NAV["ATT&CK Navigator"]:::report
        CSV["CSV / JSON"]:::report
    end

    LIVE --> A1 --> DL
    DUMP --> DL
    VMSNAP --> A2 --> DL
    HW --> A3 --> DL
    FW --> A4 --> DL
    GPUD --> A5 --> DL
    BIN --> BA2["Binary Analysis<br/>(LIEF)"]:::instrument

    DL --> PTW --> V3 --> DET
    DL --> MFS --> DET
    DL --> YARA --> DET
    DL --> STRCAR --> DET
    DET --> ARTIF
    DET --> SCORE

    SCORE --> HTML
    SCORE --> STIXO
    SCORE --> NAV
    SCORE --> CSV

    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef hardware fill:#ff8787,stroke:#e03131,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
    classDef instrument fill:#3bc9db,stroke:#1098ad,color:#1a1a2e
```

---

## Capabilities

### Memory Forensics

| Feature | Description |
|---------|-------------|
| **Multi-format support** | Raw, LiME, ELF core, Windows crashdump, hibernation files --- all via mmap for efficient large-file access |
| **Dual analysis engine** | Volatility 3 (library API, not subprocess) for deep analysis; MemProcFS for filesystem-like access and scatter-read performance |
| **Cross-platform acquisition** | AVML and LiME on Linux, OSXPmem on macOS, WinPmem on Windows, plus live `/proc/kcore` and `/dev/mem` access |
| **Symbol management** | Auto-download from Volatility symbol server, local caching, custom ISF generation via `dwarf2json` |
| **YARA scanning** | Per-process, per-region, and physical memory scanning with bundled rule sets for malware, credentials, and exploits |

### System Tracing

| Feature | Description |
|---------|-------------|
| **eBPF (Linux)** | BCC-based kernel tracing with per-CPU ring buffers, template-generated BPF C programs, and PID filter push-down |
| **DTrace (macOS)** | D script generation from abstract probe specs, structured output parsing |
| **ETW (Windows)** | Kernel provider subscriptions for process, file, network, and memory events |
| **Unified event schema** | `MonitorEvent` with dual timestamps (monotonic + wall-clock), process context, syscall details, and semantic args |
| **Filter DSL** | Platform-independent filter expressions with best-effort kernel push-down and user-space residual evaluation |

```mermaid
flowchart LR
    subgraph Backends["Platform Backends"]
        EBPF["eBPF<br/>(Linux)"]:::instrument
        DTRACE["DTrace<br/>(macOS)"]:::instrument
        ETW2["ETW<br/>(Windows)"]:::instrument
    end

    RB["Kernel Ring Buffer"]:::core

    subgraph TEB["TraceEventBus (async fan-out)"]
        PUB["publish_async()"]:::core
        Q1["Subscriber Queue 1<br/>(maxlen=10000)"]:::analysis
        Q2["Subscriber Queue 2<br/>(maxlen=10000)"]:::analysis
        Q3["Subscriber Queue N<br/>(maxlen=10000)"]:::analysis
        DROP["Drop Counter<br/>(per-queue)"]:::threat
    end

    subgraph Consumers["Subscriber Tasks"]
        C1["Filter + Display<br/>(Rich table)"]:::report
        C2["Anomaly Detector<br/>(scoring)"]:::detect
        C3["Event Logger<br/>(JSON export)"]:::report
    end

    EBPF & DTRACE & ETW2 --> RB
    RB --> PUB
    PUB --> Q1 & Q2 & Q3
    Q1 --> C1
    Q2 --> C2
    Q3 --> C3
    Q1 & Q2 & Q3 -.->|"queue full"| DROP

    classDef core fill:#868e96,stroke:#495057,color:#fff
    classDef instrument fill:#3bc9db,stroke:#1098ad,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
    classDef threat fill:#ff6b6b,stroke:#e03131,color:#fff
```

Each subscriber gets an independent async queue. Slow consumers don't block others --- when a queue is full, events are dropped (not backpressured) and the per-queue drop counter increments. Filters can be pushed down to the kernel backend (e.g., eBPF PID filtering) for efficiency.

### Application Instrumentation

| Feature | Description |
|---------|-------------|
| **Frida integration** | Attach/spawn, dynamic function hooking, JS script injection, memory read/write, module enumeration |
| **Binary analysis** | LIEF-based PE/ELF/Mach-O parsing --- sections, imports, exports, symbols, architecture detection |
| **Static reassembly** | Binary patching with trampoline injection: stolen-byte computation via Capstone, `.dvmon` section insertion, prologue redirection |
| **Pre-built scripts** | Process, file I/O, network, and API monitors; SSL pinning bypass for encrypted traffic analysis |

### VM State Imaging

| Feature | Description |
|---------|-------------|
| **QEMU/KVM** | libvirt API for VM enumeration, memory-inclusive snapshots, `virsh dump --memory-only` extraction |
| **VirtualBox** | `vboxmanage` CLI for VM listing, snapshots, `debugvm dumpvmcore` memory extraction |
| **VMware** | `vmrun` CLI for VM management, `.vmem` sidecar file extraction |

### Detection & Scanning

| Feature | Description |
|---------|-------------|
| **DKOM detection** | Cross-reference process lists from PsActiveProcessHead, CSRSS handles, PspCidTable, session lists |
| **Injection detection** | 12 MITRE T1055 sub-techniques: process hollowing, thread hijacking, PEB masquerading, RWX VAD analysis |
| **Hook detection** | SSDT hook detection, inline hook detection (JMP prologue patches) |
| **Encryption key recovery** | AES-128/256 key schedule detection, RSA private key structures, BitLocker FVEK signatures |
| **Anomaly scoring** | Heuristic feature analysis (RWX regions, unknown modules, heap entropy) with optional scikit-learn Isolation Forest |
| **IoC matching** | IP, domain, hash, URL, mutex, and string indicators against memory and file targets |

### Hardware-Assisted Memory Forensics

| Feature | Description |
|---------|-------------|
| **DMA acquisition (PCILeech)** | Non-cooperative physical memory capture over PCIe, Thunderbolt, or FireWire using FPGA boards (Screamer, SP605). Zero forensic footprint on the target; rootkits cannot intercept hardware DMA reads. Based on Ulf Frisk's PCILeech and leechcore library |
| **Cold boot capture** | DRAM remanence exploitation per Halderman et al. 2008 ("Lest We Remember"). Bit-decay confidence modeling as a function of temperature and elapsed time. DDR3/DDR4 memory controller descrambling per Bauer et al. 2016 |
| **JTAG extraction** | Boundary-scan memory reads from embedded, mobile, and IoT devices via OpenOCD, RIFF Box, or Easy-JTAG. Conforms to IEEE 1149.1 and NIST SP 800-101r1 physical extraction levels |
| **Chip-off / ISP** | Post-mortem NAND/eMMC raw imaging from desoldered flash chips or in-system programming probes. FTL reconstruction exposes wear-leveling residue and logically deleted pages invisible to filesystem tools |
| **GPU VRAM extraction** | CUDA `cuMemcpyDtoH` and OpenCL readback of GPU device memory. Recovers cryptocurrency wallet keys, ML model weights, rendered framebuffers, and hashcat residue that are invisible to CPU-side memory dumps |
| **SPI flash dumping** | Firmware image extraction via software (flashrom, CHIPSEC) or hardware (Bus Pirate, Dediprog, CH341A). Enables UEFI rootkit detection and firmware integrity verification |
| **Intel Processor Trace** | Branch-level execution recording via `perf_event_open()` and Intel `libipt` decoder. Invisible to and untamperable by malware; near-zero runtime overhead (Ge et al. ASPLOS 2017, "Griffin") |
| **ARM CoreSight** | Trace infrastructure for Cortex-A processors providing non-invasive instruction flow capture |
| **Live VM introspection** | LibVMI and DRAKVUF integration for transparent guest memory and register access via EPT-based invisible breakpoints (Lengyel et al. ACSAC 2014). Transforms VM analysis from passive snapshot to active real-time introspection |

```mermaid
flowchart TD
    subgraph HardwareSources["Hardware Acquisition Sources"]
        PCIE["PCIe / Thunderbolt<br/>(FPGA: Screamer, SP605)"]:::hardware
        FW1394["FireWire / IEEE 1394"]:::hardware
        DIMM["Physical DIMM<br/>(cold boot)"]:::hardware
        JTAGP["JTAG Probe<br/>(OpenOCD, RIFF)"]:::hardware
        ISPPR["ISP Probe<br/>(eMMC CMD/CLK/DAT)"]:::hardware
        CHIPOFF["Desoldered Flash<br/>(NAND/eMMC programmer)"]:::hardware
        SPIHW["SPI Probe<br/>(Bus Pirate, Dediprog)"]:::hardware
        GPUDEV["GPU Device<br/>(NVIDIA, AMD)"]:::hardware
    end

    subgraph Providers["Acquisition Providers"]
        PCIL["PCILeech<br/>via leechcore"]:::source
        CBPROV["Cold Boot Provider<br/>(remanence model +<br/>DDR descrambler)"]:::source
        JTAGPROV["JTAG Provider<br/>(OpenOCD backend)"]:::source
        COPROV["Chip-Off Provider<br/>(FTL reconstruction)"]:::source
        ISPPROV["ISP Provider"]:::source
        SPIPROV["SPI Flash Provider<br/>(flashrom / CHIPSEC)"]:::source
        GPUPROV["GPU Provider<br/>(CUDA / OpenCL)"]:::source
    end

    subgraph Layers["DataLayer Implementations"]
        DMA_LAYER["DMA Live Layer<br/>(real-time read)"]:::analysis
        CB_LAYER["Cold Boot Layer<br/>(decay confidence)"]:::analysis
        NAND_LAYER["NAND Layer<br/>(page/block geometry)"]:::analysis
        EMMC_LAYER["eMMC Layer<br/>(partition table)"]:::analysis
        SPI_LAYER["SPI Flash Layer<br/>(region map)"]:::analysis
        UEFI_LAYER["UEFI Volume Layer<br/>(FFS + GUID)"]:::analysis
        GPU_LAYER["GPU Layer<br/>(local/shared/const)"]:::analysis
    end

    ANALYSIS["Analysis Pipeline<br/>(Volatility 3, MemProcFS,<br/>Page Table Walker,<br/>Detection Modules)"]:::detect

    PCIE --> PCIL --> DMA_LAYER
    FW1394 --> PCIL
    DIMM --> CBPROV --> CB_LAYER
    JTAGP --> JTAGPROV --> NAND_LAYER
    ISPPR --> ISPPROV --> EMMC_LAYER
    CHIPOFF --> COPROV --> NAND_LAYER
    SPIHW --> SPIPROV --> SPI_LAYER
    SPIPROV --> UEFI_LAYER
    GPUDEV --> GPUPROV --> GPU_LAYER

    DMA_LAYER --> ANALYSIS
    CB_LAYER --> ANALYSIS
    NAND_LAYER --> ANALYSIS
    EMMC_LAYER --> ANALYSIS
    SPI_LAYER --> ANALYSIS
    UEFI_LAYER --> ANALYSIS
    GPU_LAYER --> ANALYSIS

    classDef hardware fill:#ff8787,stroke:#e03131,color:#1a1a2e
    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
```

### Advanced Memory Analysis

| Feature | Description |
|---------|-------------|
| **Page table reconstruction** | Independent CR3 → PML4 → PDPT → PD → PT walk on raw physical memory, supporting 4K/2M/1G pages and 5-level (LA57) paging. Brute-force CR3 candidate scanning as fallback when OS structures are corrupted. Based on Intel SDM Vol. 3A Ch. 4 and Dolan-Gavitt's robust enumeration work |
| **Virtual address layer** | `DataLayer` implementation that transparently translates virtual address reads to physical, handling cross-page-boundary access. Enables per-process virtual address space analysis without Volatility |
| **Multi-encoding string carving** | Extract printable strings across ASCII, UTF-8, UTF-16LE/BE, Shift-JIS, EUC-KR, ISO-8859-1, and CP1252 with Shannon entropy pre-filtering to skip encrypted/compressed regions (threshold-configurable) |
| **TCP/IP stack reconstruction** | Network connection recovery via Windows pool tag scanning (TcpE, TcpL, UdpA) and Linux `inet_sock` signature matching. Extracts protocol, addresses, ports, TCP state, and owning PID |
| **Command history extraction** | Shell command recovery from memory for cmd.exe (UTF-16LE COMMAND_HISTORY), PowerShell (ConsoleHost/PSReadLine), and bash (HIST_ENTRY) via heuristic signature and command-pattern matching |

```mermaid
flowchart LR
    subgraph PhysMem["Physical Memory Image"]
        RAW["Raw / LiME /<br/>ELF Core Dump"]:::source
    end

    subgraph Translation["Page Table Reconstruction"]
        CR3["CR3 Discovery<br/>(brute-force scan or<br/>EPROCESS extraction)"]:::analysis
        PML4["PML4 Walk<br/>(512 entries)"]:::analysis
        PDPT["PDPT Walk"]:::analysis
        PD["PD Walk"]:::analysis
        PT["PT Walk<br/>(4K page)"]:::analysis
        VIRT["Virtual Address<br/>Layer"]:::analysis
    end

    subgraph Analysis["Per-Process Analysis"]
        HEAP["Heap Forensics<br/>(freed data recovery)"]:::detect
        NET["TCP/IP Stack<br/>Reconstruction"]:::detect
        STR["String Carving<br/>(multi-encoding)"]:::detect
        CMD["Command History<br/>(cmd, PS, bash)"]:::detect
        ENV["Environment<br/>Variables"]:::detect
    end

    RAW --> CR3 --> PML4 --> PDPT --> PD --> PT --> VIRT
    PDPT -.->|"1G huge page<br/>(PS bit set)"| VIRT
    PD -.->|"2M large page<br/>(PS bit set)"| VIRT

    VIRT --> HEAP
    VIRT --> NET
    VIRT --> STR
    VIRT --> CMD
    VIRT --> ENV

    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
```

#### x86-64 Virtual Address Translation

Each virtual address is decomposed into index fields that walk the 4-level page table hierarchy. The PS (Page Size) bit at the PD or PDPT level short-circuits the walk for 2M or 1G large pages.

```text
 x86-64 Virtual Address (48-bit canonical form)
 ================================================================

  63        48 47    39 38    30 29    21 20    12 11         0
 +-----------+--------+--------+--------+--------+------------+
 | Sign Ext  | PML4   | PDPT   |   PD   |   PT   |   Offset   |
 | (copy of  | Index  | Index  | Index  | Index  |  (12 bits)  |
 |  bit 47)  | 9 bits | 9 bits | 9 bits | 9 bits |            |
 +-----------+---+----+---+----+---+----+---+----+------------+
                 |        |        |        |
    CR3 ------->+        |        |        |
                 v        |        |        |
              PML4 Table  |        |        |     Page Sizes:
              (512 entries)|       |        |     ============
                 |        v        |        |
                 +-->  PDPT Table  |        |     1G huge page
                    (512 entries)  |        |       = PDPT entry
                          |       v        |         with PS=1
                          +--> PD Table    |
                             (512 entries) |      2M large page
                                  |       v        = PD entry
                                  +--> PT Table      with PS=1
                                     (512 entries)
                                          |       4K standard
                                          v        = PT entry
                                     Physical        (normal)
                                      Address

 With LA57 (5-level paging):  adds PML5 index at bits [56:48]
```

### Firmware & Rootkit Detection

| Feature | Description |
|---------|-------------|
| **UEFI rootkit detection** | Signature scanning for known firmware implants (LoJax/APT28, MosaicRegressor) and rogue DXE drivers. Based on ESET 2018 and Kaspersky 2020 research |
| **Firmware integrity** | Compare extracted SPI flash contents against known-good hash databases. Verify BIOS write protection (CHIPSEC) and Secure Boot configuration |
| **Bootkit detection** | MBR/VBR integrity verification against known-good boot code templates. Detect INT 13h hooks and encrypted JMP sequences (TDL4, FinSpy). Maps to ATT&CK T1542.003 |
| **PatchGuard bypass detection** | Identify Windows KPP circumvention via `KiErrata` integrity checks, DPC routine validation, and `HalPrivateDispatchTable` modification scanning. Maps to ATT&CK T1562.001 |
| **Hypervisor rootkit detection** | Detect Blue Pill (Rutkowska 2006) and SubVirt (King et al. 2006) style thin hypervisors via VMCS signature scanning in physical memory, CPUID timing analysis, and unexpected VMX MSR values. Maps to ATT&CK T1564.006 |
| **Driver signature verification** | Cross-reference in-memory driver image hashes against known-good databases. Section-by-section integrity comparison detects runtime patching |

---

## Real-World Forensic Scenarios

### Scenario 1: Incident Response --- Memory Acquisition and Analysis

A SOC analyst receives an alert for suspicious PowerShell activity on a Windows server. Deep View acquires the system's physical memory, runs process enumeration and YARA scans to identify the malicious process, and generates an ATT&CK-mapped report.

```mermaid
sequenceDiagram
    participant Analyst
    participant DeepView
    participant Target as Target System
    participant Vol3 as Volatility 3
    participant YARA

    rect rgba(255,169,77,0.08)
        Note over Analyst,Target: Acquisition Phase
        Analyst->>DeepView: deepview memory acquire --method winpmem -o server.raw
        DeepView->>Target: WinPmem driver loads, captures physical memory
        Target-->>DeepView: Raw dump (server.raw) + SHA-256 hash
    end

    rect rgba(116,192,252,0.08)
        Note over Analyst,Vol3: Analysis Phase
        Analyst->>DeepView: deepview memory analyze --image server.raw --plugin pslist
        DeepView->>Vol3: Run windows.pslist.PsList
        Vol3-->>DeepView: Process table (PID, PPID, name, create time)
        DeepView-->>Analyst: Rich table output with process tree
    end

    rect rgba(192,132,252,0.08)
        Note over Analyst,YARA: Detection Phase
        Analyst->>DeepView: deepview memory scan --image server.raw --rules malware.yar
        DeepView->>YARA: Scan all memory regions
        YARA-->>DeepView: Matches: SuspiciousStrings at PID 4832 (powershell.exe)
        DeepView-->>Analyst: Scan results with offsets, rule names, matched data
    end

    rect rgba(105,219,124,0.08)
        Note over Analyst,DeepView: Export Phase
        Analyst->>DeepView: deepview report export --format stix -o findings.json
        DeepView-->>Analyst: STIX 2.1 bundle with ATT&CK technique references
    end
```

**Applicable techniques:** T1059.001 (PowerShell), T1003 (Credential Dumping), T1055 (Process Injection)

### Scenario 2: Malware Investigation --- Rootkit Detection

A threat hunter suspects a Linux server has been compromised by a kernel rootkit that hides processes using DKOM. Deep View cross-references multiple kernel data structures to reveal hidden processes.

```mermaid
flowchart TD
    A["Acquire memory<br/>deepview memory acquire --method avml"]:::source --> B["Parse memory dump<br/>(LiME format auto-detected)"]:::source
    B --> C["Enumerate processes from<br/>multiple kernel structures"]:::analysis

    C --> D["PsActiveProcessHead<br/>(linked list walk)"]:::analysis
    C --> E["PspCidTable<br/>(handle table)"]:::analysis
    C --> F["Session process list"]:::analysis
    C --> G["Thread scanning"]:::analysis

    D --> H{"Cross-reference<br/>PID sets"}:::decision
    E --> H
    F --> H
    G --> H

    H -->|PIDs match| I["Clean processes"]:::clean
    H -->|PID mismatch| J["ALERT: Hidden process detected<br/>DKOM manipulation (T1014)"]:::threat

    J --> K["Generate ATT&CK Navigator layer"]:::report
    J --> L["Export STIX 2.1 indicators"]:::report
    J --> M["HTML forensic report"]:::report

    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef decision fill:#ffd43b,stroke:#f08c00,color:#1a1a2e
    classDef clean fill:#51cf66,stroke:#2f9e44,color:#1a1a2e
    classDef threat fill:#ff6b6b,stroke:#e03131,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
```

**Applicable techniques:** T1014 (Rootkit), T1574 (Hijack Execution Flow), T1562.001 (Disable Security Tools)

### Scenario 3: Live System Monitoring --- eBPF-Based Threat Hunting

An analyst monitors a potentially compromised Linux system in real time using eBPF probes to capture syscall activity, correlating process creation, network connections, and file access patterns.

```mermaid
sequenceDiagram
    participant Analyst
    participant DeepView
    participant Kernel as Linux Kernel
    participant BPF as eBPF Subsystem

    rect rgba(59,201,219,0.08)
        Note over DeepView,BPF: Program Compilation & Loading
        Analyst->>DeepView: deepview trace syscall --duration 60 --syscall execve connect openat
        DeepView->>BPF: Compile and load BPF C program
        BPF->>Kernel: Attach tracepoints (sys_enter_execve, sys_enter_connect, sys_enter_openat)
        Kernel-->>BPF: Events via ring buffer
    end

    rect rgba(192,132,252,0.08)
        Note over Analyst,BPF: Real-Time Event Collection
        loop Every event
            BPF-->>DeepView: MonitorEvent (pid, comm, syscall, args, timestamp)
            DeepView->>DeepView: Apply user-space filter residuals
            DeepView-->>Analyst: Formatted event stream (Rich table)
        end
    end

    Note over Analyst,BPF: Analyst observes /bin/sh spawned by httpd,<br/>followed by connect() to external IP

    rect rgba(116,192,252,0.08)
        Note over Analyst,BPF: Focused PID Tracing
        Analyst->>DeepView: deepview trace network --pid 8472 --duration 30
        DeepView->>BPF: Attach kprobe:tcp_v4_connect filtered by PID 8472
        BPF-->>DeepView: TCP connection events (saddr, daddr, dport)
        DeepView-->>Analyst: Network activity for suspect process
    end
```

**Applicable techniques:** T1059.004 (Unix Shell), T1071.001 (Web Protocols), T1041 (Exfiltration Over C2)

### Scenario 4: Virtual Machine Forensics

An investigator needs to analyze a potentially compromised virtual machine without alerting the attacker. Deep View takes a live snapshot, extracts the memory, and performs offline analysis.

```mermaid
sequenceDiagram
    participant Investigator
    participant DeepView
    participant KVM as QEMU/KVM (libvirt)
    participant Vol3 as Volatility 3

    rect rgba(255,169,77,0.08)
        Note over Investigator,KVM: VM Enumeration
        Investigator->>DeepView: deepview vm list --hypervisor qemu
        DeepView->>KVM: libvirt.listDomainsID() + listDefinedDomains()
        KVM-->>DeepView: VM list (name, UUID, state, memory)
        DeepView-->>Investigator: Table of VMs
    end

    rect rgba(255,169,77,0.12)
        Note over Investigator,KVM: Snapshot & Extraction
        Investigator->>DeepView: deepview vm snapshot --vm-id web-server --name forensic-snap
        DeepView->>KVM: domain.snapshotCreateXML (memory-inclusive)
        KVM-->>DeepView: Snapshot created

        Investigator->>DeepView: deepview vm extract --vm-id web-server -o vm-memory.raw
        DeepView->>KVM: virsh dump --memory-only
        KVM-->>DeepView: Memory dump (vm-memory.raw)
    end

    rect rgba(116,192,252,0.08)
        Note over Investigator,Vol3: Offline Analysis
        Investigator->>DeepView: deepview memory analyze --image vm-memory.raw --plugin pslist
        DeepView->>Vol3: Process enumeration
        Vol3-->>DeepView: Process list
        DeepView-->>Investigator: Results + timeline
    end

    Note over Investigator: VM continues running undisturbed
```

**Applicable techniques:** T1497 (Virtualization/Sandbox Evasion), T1078 (Valid Accounts)

### Scenario 5: Binary Analysis and Instrumentation

A malware analyst receives a suspicious ELF binary. Deep View analyzes its structure, identifies security-sensitive API calls, and creates an instrumented version that logs all function calls for dynamic analysis.

```mermaid
flowchart TD
    A["Suspect binary<br/>deepview instrument analyze --binary suspect.elf"]:::source --> B["LIEF parses ELF headers<br/>sections, imports, exports, symbols"]:::analysis
    B --> C["InstrumentationPointFinder<br/>identifies hookable functions"]:::analysis

    C --> D["Exported functions"]:::source
    C --> E["Security-sensitive APIs<br/>(connect, execve, mmap, dlopen...)"]:::source
    C --> F["Symbol table functions"]:::source

    D & E & F --> G["Generate hook plan"]:::analysis

    G --> H{"Choose approach"}:::decision

    H -->|Dynamic| I["deepview instrument spawn --program suspect.elf --hooks hooks.json"]:::instrument
    I --> J["Frida attaches before main()"]:::instrument
    J --> K["Interceptor.attach() on each target"]:::instrument
    K --> L["Real-time API trace via EventBus"]:::report

    H -->|Static| M["deepview instrument patch --binary suspect.elf -o monitored.elf --strategy security"]:::detect
    M --> N["Compute stolen bytes (Capstone)"]:::detect
    N --> O["Generate trampolines (x86_64/aarch64)"]:::detect
    O --> P["Add .dvmon section via LIEF"]:::detect
    P --> Q["Patch function prologues with JMP"]:::detect
    Q --> R["Write instrumented binary"]:::detect
    R --> S["Execute monitored.elf in sandbox"]:::report

    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef decision fill:#ffd43b,stroke:#f08c00,color:#1a1a2e
    classDef instrument fill:#3bc9db,stroke:#1098ad,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
```

**Applicable techniques:** T1027 (Obfuscated Files), T1059 (Command Execution), T1055 (Process Injection)

### Scenario 6: Threat Intelligence Integration

After completing a forensic investigation, the analyst exports all findings to organizational threat intelligence platforms and generates ATT&CK coverage maps for the security team.

```mermaid
flowchart LR
    subgraph DeepView["Deep View Analysis"]
        D1["DKOM Detection<br/>(T1014)"]:::threat
        D2["Process Hollowing<br/>(T1055.012)"]:::threat
        D3["SSDT Hooks<br/>(T1574.013)"]:::threat
        D4["Injected Code<br/>(T1055)"]:::threat
        D5["PEB Masquerade<br/>(T1036.005)"]:::threat
    end

    subgraph Export["Export Pipeline"]
        STIX["STIX 2.1 Bundle<br/>(indicators, observed-data)"]:::report
        NAV["ATT&CK Navigator<br/>Layer JSON"]:::report
        RPT["HTML Forensic Report"]:::report
        TL["Event Timeline"]:::report
    end

    subgraph Consume["Downstream Systems"]
        TIP["Threat Intel Platform<br/>(MISP, OpenCTI)"]:::analysis
        SIEM["SIEM<br/>(Splunk, Elastic)"]:::analysis
        SOC["SOC Dashboard"]:::analysis
        CASE["Case Management"]:::analysis
    end

    D1 & D2 & D3 & D4 & D5 --> STIX
    D1 & D2 & D3 & D4 & D5 --> NAV
    D1 & D2 & D3 & D4 & D5 --> RPT
    D1 & D2 & D3 & D4 & D5 --> TL

    STIX -->|TAXII 2.1| TIP
    STIX -->|JSON import| SIEM
    NAV --> SOC
    RPT --> CASE
    TL --> SIEM

    classDef threat fill:#ff6b6b,stroke:#e03131,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
```

---

## Platform Support

| Capability | Linux | macOS | Windows |
|:-----------|:-----:|:-----:|:-------:|
| Memory acquisition | LiME, AVML, /proc/kcore | OSXPmem | WinPmem |
| DMA acquisition (PCILeech) | PCIe, Thunderbolt | Thunderbolt | PCIe, Thunderbolt |
| Cold boot capture | Yes | Yes | Yes |
| JTAG / chip-off / ISP | Yes | Yes | Yes |
| GPU VRAM extraction | CUDA, OpenCL | Metal, OpenCL | CUDA, OpenCL |
| SPI flash / firmware | flashrom, CHIPSEC | flashrom | CHIPSEC |
| Memory analysis (Volatility 3) | Yes | Yes | Yes |
| Memory analysis (MemProcFS) | Yes | Yes | Yes |
| Page table reconstruction | Yes | Yes | Yes |
| String carving (multi-encoding) | Yes | Yes | Yes |
| TCP/IP stack reconstruction | Yes | -- | Yes |
| Command history extraction | bash | bash | cmd, PowerShell |
| YARA scanning | Yes | Yes | Yes |
| System tracing | eBPF/BCC | DTrace | ETW |
| Intel Processor Trace | Broadwell+ | -- | -- |
| ARM CoreSight | Cortex-A | Apple Silicon | -- |
| Frida instrumentation | Yes | Yes | Yes |
| Binary analysis (LIEF) | ELF | Mach-O | PE |
| Binary reassembly | ELF | Mach-O | PE |
| VM connectors | QEMU/KVM, VBox, VMware | VBox, VMware | VBox, VMware |
| Live VM introspection (LibVMI) | KVM, Xen | -- | -- |
| DKOM detection | Yes | -- | Yes |
| Injection detection | Yes | Yes | Yes |
| Encryption key scanning | Yes | Yes | Yes |
| Rootkit detection (hypervisor, bootkit) | Yes | -- | Yes |
| Firmware / UEFI analysis | Yes | Yes | Yes |
| STIX 2.1 export | Yes | Yes | Yes |
| ATT&CK mapping | Yes | Yes | Yes |

---

## Quick Start

### Installation

```bash
# Core installation
pip install deepview

# With memory forensics support
pip install "deepview[memory]"

# With instrumentation support
pip install "deepview[instrumentation]"

# Hardware-assisted acquisition (DMA via PCILeech)
pip install "deepview[hardware]"

# Firmware / UEFI forensics
pip install "deepview[firmware]"

# GPU VRAM forensics
pip install "deepview[gpu]"

# ML-based anomaly detection
pip install "deepview[ml]"

# Full installation (all optional dependencies)
pip install "deepview[all]"

# Development installation
git clone <repo-url> && cd deepview
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Check system capabilities
deepview doctor

# List installed plugins
deepview plugins

# Acquire memory from a live Linux system
sudo deepview memory acquire --method avml -o memory.raw

# Analyze a memory image
deepview memory analyze --image memory.raw --plugin pslist --engine volatility

# YARA scan a memory image
deepview memory scan --image memory.raw --rules /path/to/rules.yar

# Trace syscalls on a live system (Linux)
sudo deepview trace syscall --pid 1234 --duration 30

# Analyze a binary
deepview instrument analyze --binary /usr/bin/suspect

# Attach Frida to a running process
deepview instrument attach --pid 5678 --hooks hooks.json

# Patch a binary with monitoring hooks
deepview instrument patch --binary suspect --output monitored --strategy security

# List virtual machines
deepview vm list --hypervisor qemu

# Snapshot and extract VM memory
deepview vm snapshot --vm-id myvm --name forensic
deepview vm extract --vm-id myvm -o vm-memory.raw

# Generate reports
deepview report generate --template html -o report.html
deepview report export --format stix -o findings.json
deepview report timeline -o timeline.json
```

---

## CLI Reference

```
deepview [global-options] <command> [subcommand] [options]

Global Options:
  --config PATH              Configuration file
  --output-format FORMAT     json | table | csv | timeline
  --log-level LEVEL          debug | info | warning | error
  --plugin-path PATH         Additional plugin directories
  --no-color                 Disable colored output
  --version                  Show version

Commands:
  doctor                     Check system capabilities and tools
  plugins                    List installed plugins

  memory acquire             Acquire memory from live system or via hardware
  memory analyze             Run analysis plugin on memory image
  memory symbols             Manage kernel symbol tables
  memory scan                YARA scan on memory image
  memory strings             Carve strings (multi-encoding, entropy-filtered)
  memory pagetables          Walk page tables from CR3
  memory netstat             Reconstruct TCP/IP connections from memory
  memory history             Extract shell command history
  memory diff                Compare two memory snapshots
  memory baseline build      Build known-good memory profile
  memory baseline compare    Compare image against baseline

  trace syscall              Trace system calls
  trace network              Trace network activity
  trace filesystem           Trace file system operations
  trace process              Trace process creation/termination
  trace custom               Run custom eBPF/DTrace/ETW program

  instrument attach          Attach to running process (Frida)
  instrument spawn           Launch and instrument a program
  instrument patch           Static binary patching with hooks
  instrument analyze         Analyze binary structure (LIEF)

  vm list                    List virtual machines
  vm snapshot                Create VM snapshot
  vm extract                 Extract VM memory/state
  vm analyze                 Snapshot + analyze in one step
  vm introspect              Live VM memory read via LibVMI

  scan yara                  Run YARA rules against target
  scan ioc                   Run IoC indicator matching
  scan rules                 Manage YARA rule sets
  scan firmware              UEFI/SPI flash integrity check
  scan rootkit               Hypervisor, bootkit, PatchGuard detection

  report generate            Create HTML/Markdown report
  report timeline            Generate event timeline
  report export              Export STIX 2.1 / ATT&CK format
```

---

## Plugin System

Deep View uses a three-tier plugin discovery mechanism:

1. **Built-in plugins** --- ship with the package, registered via `@register_plugin` decorators
2. **Entry point plugins** --- third-party packages register via `[project.entry-points."deepview.plugins"]` in their `pyproject.toml`
3. **Directory plugins** --- Python files dropped into `~/.deepview/plugins/` or paths specified via `--plugin-path`

```mermaid
flowchart TD
    subgraph Discovery["Three-Tier Plugin Discovery"]
        T1["Tier 1: Built-in<br/>import deepview.plugins.builtin"]:::analysis
        T2["Tier 2: Entry Points<br/>importlib.metadata.entry_points<br/>('deepview.plugins')"]:::analysis
        T3["Tier 3: Directory Scan<br/>~/.deepview/plugins/*.py<br/>or --plugin-path"]:::analysis
    end

    DEC["@register_plugin<br/>decorator fires"]:::instrument
    EP["Load module via<br/>entry point"]:::instrument
    DYN["Dynamic spec loader<br/>(importlib)"]:::instrument

    REG["PluginRegistry<br/>(unified catalog)"]:::core

    subgraph Execution["Plugin Lifecycle"]
        INST["registry.instantiate<br/>(name, config)"]:::core
        REQ["plugin.get_requirements()"]:::source
        RUN["plugin.run()"]:::detect
        RES["PluginResult<br/>(columns + rows)"]:::report
    end

    REND["ResultRenderer<br/>(table / JSON / CSV)"]:::report

    T1 --> DEC --> REG
    T2 --> EP --> REG
    T3 --> DYN --> REG
    REG --> INST --> REQ --> RUN --> RES --> REND

    classDef core fill:#868e96,stroke:#495057,color:#fff
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef instrument fill:#3bc9db,stroke:#1098ad,color:#1a1a2e
    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
```

### Writing a Plugin

```python
from deepview.plugins.base import register_plugin
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.core.types import PluginCategory

@register_plugin(
    name="my_analysis",
    category=PluginCategory.MEMORY_ANALYSIS,
    description="Custom memory analysis plugin",
    tags=["custom", "analysis"],
)
class MyAnalysisPlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="image_path", description="Path to memory image"),
        ]

    def run(self) -> PluginResult:
        image_path = self._config.get("image_path")
        # ... perform analysis using self._context ...
        return PluginResult(
            columns=["Finding", "Offset", "Severity"],
            rows=[{"Finding": "Example", "Offset": "0x1000", "Severity": "high"}],
        )
```

### Built-in Plugins

| Plugin | Category | Description |
|--------|----------|-------------|
| `pslist` | Memory Analysis | List processes from memory image (Volatility 3 / MemProcFS) |
| `netstat` | Network Forensics | Reconstruct TCP/UDP connections from kernel structures (Windows pool tags, Linux inet_sock) |
| `malfind` | Malware Detection | Detect suspicious memory regions, injected code, hollow processes |
| `dkom_detect` | Malware Detection | Detect hidden processes via kernel structure cross-referencing |
| `timeliner` | Timeline | Extract temporal artifacts across memory structures |
| `credentials` | Credentials | Extract password hashes, private keys, and session tokens |
| `pagetable_walk` | Memory Analysis | Walk x86-64 page tables (4/5-level) to enumerate virtual-to-physical mappings |
| `strings` | Memory Analysis | Carve printable strings across multiple encodings with entropy filtering |
| `command_history` | Artifact Recovery | Extract shell command history (cmd.exe, PowerShell, bash) from process memory |

---

## Detection Techniques

### MITRE ATT&CK Coverage

Deep View maps all detections to MITRE ATT&CK techniques and generates Navigator layers for visualization.

```mermaid
graph LR
    ROOT(("Deep View<br/>Detections")):::core

    subgraph DE["Defense Evasion"]
        T1014["T1014 Rootkit"]:::threat
        T1014a["DKOM hidden processes"]:::threat
        T1014b["Driver hiding"]:::threat
        T1014c["Driver signature mismatch"]:::threat
        T1055["T1055 Process Injection"]:::threat
        T1055_1["T1055.001 DLL Injection"]:::threat
        T1055_2["T1055.002 PE Injection"]:::threat
        T1055_3["T1055.003 Thread Hijacking"]:::threat
        T1055_4["T1055.004 APC Injection"]:::threat
        T1055_12["T1055.012 Process Hollowing"]:::threat
        T1055_13["T1055.013 Process Doppelganging"]:::threat
        T1055_14["T1055.014 VDSO Hijacking"]:::threat
        T1574["T1574 Hijack Execution Flow"]:::threat
        T1574_13["T1574.013 KernelCallbackTable"]:::threat
        T1574a["SSDT hooks"]:::threat
        T1574b["Inline hooks"]:::threat
        T1036["T1036.005 Match Legitimate Name"]:::threat
        T1036a["PEB masquerading"]:::threat
        T1562["T1562.001 Disable Security Tools"]:::threat
        T1562a["PatchGuard bypass detection"]:::threat
        T1564["T1564.006 Run Virtual Instance"]:::threat
        T1564a["Hypervisor rootkit detection"]:::threat
        T1564b["VMCS scanning"]:::threat
        T1564c["CPUID timing analysis"]:::threat
    end

    subgraph PE["Persistence"]
        T1542["T1542 Pre-OS Boot"]:::source
        T1542_1["T1542.001 System Firmware"]:::source
        T1542_1a["UEFI rootkit detection"]:::source
        T1542_1b["SPI flash integrity"]:::source
        T1542_3["T1542.003 Bootkit"]:::source
        T1542_3a["MBR/VBR integrity"]:::source
        T1542_3b["Boot code tampering"]:::source
    end

    subgraph CA["Credential Access"]
        KEYS["Encryption key recovery"]:::detect
        AES["AES-128/256 key schedules"]:::detect
        RSA["RSA private key structures"]:::detect
        BL["BitLocker FVEK"]:::detect
        DM["dm-crypt master keys"]:::detect
        TLS["TLS session keys"]:::detect
    end

    subgraph DI["Discovery"]
        PROC["Process enumeration"]:::analysis
        NETC["Network connections"]:::analysis
        MODS["Loaded modules"]:::analysis
        PTMAP["Page table mapping"]:::analysis
    end

    subgraph CO["Collection"]
        VOL["Volatile artifacts"]:::instrument
        CMDHIST["Command history"]:::instrument
        CLIP["Clipboard contents"]:::instrument
        ENVV["Environment variables"]:::instrument
    end

    ROOT --> DE
    ROOT --> PE
    ROOT --> CA
    ROOT --> DI
    ROOT --> CO

    T1014 --> T1014a & T1014b & T1014c
    T1055 --> T1055_1 & T1055_2 & T1055_3 & T1055_4
    T1055 --> T1055_12 & T1055_13 & T1055_14
    T1574 --> T1574_13 & T1574a & T1574b
    T1036 --> T1036a
    T1562 --> T1562a
    T1564 --> T1564a & T1564b & T1564c

    T1542 --> T1542_1 & T1542_3
    T1542_1 --> T1542_1a & T1542_1b
    T1542_3 --> T1542_3a & T1542_3b

    KEYS --> AES & RSA & BL & DM & TLS

    VOL --> CMDHIST & CLIP & ENVV

    classDef core fill:#868e96,stroke:#495057,color:#fff
    classDef threat fill:#ff6b6b,stroke:#e03131,color:#fff
    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef instrument fill:#3bc9db,stroke:#1098ad,color:#1a1a2e
```

### DKOM Detection

Direct Kernel Object Manipulation is detected by enumerating processes from independent kernel data structures and cross-referencing the results. A process visible in one structure but missing from another indicates deliberate hiding.

**Sources cross-referenced:**
- `PsActiveProcessHead` (doubly-linked list of `EPROCESS` structures)
- `PspCidTable` (handle table mapping PIDs to objects)
- `CSRSS` handle table (Windows session manager)
- Session process lists
- Desktop thread scanning (walk all threads, collect owning processes)

```text
 DKOM: How Hidden Processes Are Detected via Cross-Referencing
 =============================================================

 NORMAL STATE (all structures agree):

   PsActiveProcessHead:  [System] <-> [smss] <-> [csrss] <-> [malware] <-> [svchost] <-> ...
   PspCidTable:           PID 4 OK    PID 312 OK  PID 488 OK  PID 1337 OK  PID 672 OK
   CSRSS handles:         PID 4 OK    PID 312 OK  PID 488 OK  PID 1337 OK  PID 672 OK
   Thread scanning:       PID 4 OK    PID 312 OK  PID 488 OK  PID 1337 OK  PID 672 OK


 AFTER DKOM (attacker unlinks PID 1337 from PsActiveProcessHead):

   PsActiveProcessHead:  [System] <-> [smss] <-> [csrss] <-=========-> [svchost] <-> ...
                                                                ^
                                                      PID 1337 MISSING!

   PspCidTable:           PID 4 OK    PID 312 OK  PID 488 OK  PID 1337 OK  PID 672 OK
   CSRSS handles:         PID 4 OK    PID 312 OK  PID 488 OK  PID 1337 OK  PID 672 OK
   Thread scanning:       PID 4 OK    PID 312 OK  PID 488 OK  PID 1337 OK  PID 672 OK
                                                                ^^^^^^^^
                                                           STILL PRESENT!

   Result: PID 1337 found in PspCidTable + CSRSS + threads but NOT in
           PsActiveProcessHead --> DKOM DETECTED (MITRE ATT&CK T1014)
```

### Hook Detection & Trampoline Architecture

Deep View detects inline function hooks by scanning function prologues for unexpected JMP/CALL instructions. The following shows how a rootkit hooks a function and how Deep View's static binary patching uses the same trampoline technique for monitoring:

```text
 BEFORE HOOK (original function):                AFTER HOOK (rootkit-patched):
 ===================================             ===================================
 NtQuerySystemInformation:                       NtQuerySystemInformation:
   0x00: 4C 8B D1    mov r10, rcx                 0x00: E9 xx xx xx xx   jmp <detour>
   0x03: B8 36 00    mov eax, 0x36                 0x05: 00 00 00        <nop padding>
   0x06: 0F 05       syscall                       ...
   0x08: C3          ret
                                                  Detour Code (rootkit):
                                                    - Filter/modify results
                                                    - Call trampoline to run original

                                                  Trampoline (stolen bytes):
                                                    0x00: 4C 8B D1    mov r10, rcx  --|
                                                    0x03: B8 36 00    mov eax, 0x36    | stolen
                                                    0x06: E9 xx xx    jmp back (0x06) -|

 DETECTION: Scan prologue bytes for E9/FF/EB opcodes (JMP variants).
            If target address falls outside the owning module's range
            → flag as inline hook (T1574).
```

```mermaid
flowchart LR
    SCAN["Scan Function<br/>Prologues"]:::analysis
    CHECK{"First bytes =<br/>JMP/CALL opcode?<br/>(E9, FF 25, EB)"}:::decision
    SAFE["Clean Function"]:::clean
    TARGET["Resolve JMP<br/>Target Address"]:::analysis
    MOD{"Target within<br/>owning module<br/>range?"}:::decision
    HOOK["Inline Hook<br/>Detected (T1574)"]:::threat
    LEGIT["Legitimate<br/>Redirection"]:::clean

    SCAN --> CHECK
    CHECK -->|No| SAFE
    CHECK -->|Yes| TARGET --> MOD
    MOD -->|No| HOOK
    MOD -->|Yes| LEGIT

    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef decision fill:#ffd43b,stroke:#f08c00,color:#1a1a2e
    classDef clean fill:#51cf66,stroke:#2f9e44,color:#1a1a2e
    classDef threat fill:#ff6b6b,stroke:#e03131,color:#fff
```

### Process Injection Detection

| Sub-technique | Detection Method |
|:-------------|:-----------------|
| Process Hollowing (T1055.012) | PEB `ImageBaseAddress` mismatch with actual mapped image base |
| Injected Code (T1055) | VAD entries with `PAGE_EXECUTE_READWRITE`, private, no file backing |
| Thread Hijacking (T1055.003) | Thread start address outside any known module's address range |
| PEB Masquerading (T1036.005) | PEB image path or command line inconsistent with on-disk binary |

```mermaid
flowchart TD
    PROC["Target Process<br/>Memory Space"]:::analysis

    subgraph VAD["Virtual Address Descriptor Tree"]
        V1[".text (image)<br/>R-X, file-backed"]:::clean
        V2[".data (image)<br/>RW-, file-backed"]:::clean
        V3["ntdll.dll<br/>R-X, file-backed"]:::clean
        V4["Stack<br/>RW-, private"]:::clean
        V5["Heap<br/>RW-, private"]:::clean
        V6["RWX Region<br/>private, no file backing"]:::threat
        V7["Mapped DLL<br/>R-X, file-backed"]:::clean
    end

    PROC --> VAD

    subgraph Checks["Detection Checks"]
        CK1{"PEB.ImageBaseAddress<br/>== actual image base?"}:::decision
        CK2{"Any VAD with<br/>PAGE_EXECUTE_READWRITE<br/>+ private + no file?"}:::decision
        CK3{"Thread start addr<br/>inside known module<br/>range?"}:::decision
        CK4{"PEB image path<br/>== on-disk binary?"}:::decision
    end

    CK1 -->|No| H1["Process Hollowing<br/>(T1055.012)"]:::threat
    CK1 -->|Yes| OK1["Normal"]:::clean
    CK2 -->|Yes| H2["Injected Code<br/>(T1055)"]:::threat
    CK2 -->|No| OK2["Normal"]:::clean
    CK3 -->|No| H3["Thread Hijacking<br/>(T1055.003)"]:::threat
    CK3 -->|Yes| OK3["Normal"]:::clean
    CK4 -->|No| H4["PEB Masquerade<br/>(T1036.005)"]:::threat
    CK4 -->|Yes| OK4["Normal"]:::clean

    V6 -.-> CK2

    classDef clean fill:#51cf66,stroke:#2f9e44,color:#1a1a2e
    classDef threat fill:#ff6b6b,stroke:#e03131,color:#fff
    classDef decision fill:#ffd43b,stroke:#f08c00,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
```

### Encryption Key Recovery

| Key Type | Detection Method |
|:---------|:----------------|
| AES-128/256 | Key schedule entropy analysis (expanded keys exhibit >6.0 bits/byte entropy with structural word relationships) |
| RSA Private Keys | ASN.1 DER sequence detection: `SEQUENCE { INTEGER(0), INTEGER(modulus), ... }` |
| BitLocker FVEK | `-FVE-FS-` signature scanning in memory |
| dm-crypt | Master key extraction from kernel `crypt_config` structures |

```mermaid
flowchart TD
    MEM["Physical Memory<br/>(DataLayer)"]:::source

    SCAN["Sliding Window Scanner<br/>(sequential byte scan)"]:::analysis

    ENT{"Entropy Check<br/>> 6.0 bits/byte?"}:::decision

    ENT -->|No| SKIP["Skip region<br/>(low entropy = unlikely key)"]:::core
    ENT -->|Yes| CAND["Candidate Key<br/>Material"]:::analysis

    MEM --> SCAN --> ENT

    subgraph Validators["Key Type Validators"]
        AES_V["AES Validator<br/>Verify round key<br/>derivation relationships<br/>(Rcon + SubBytes + XOR)"]:::detect
        RSA_V["RSA Validator<br/>Check ASN.1 DER header<br/>(0x30 0x82 ... SEQUENCE)"]:::detect
        BL_V["BitLocker Validator<br/>Scan for -FVE-FS-<br/>metadata signature"]:::detect
        DM_V["dm-crypt Validator<br/>Locate crypt_config<br/>kernel structures"]:::detect
    end

    CAND --> AES_V & RSA_V & BL_V & DM_V

    AES_V -->|valid| AES_K["AES-128/256 Key<br/>+ confidence score"]:::report
    RSA_V -->|valid| RSA_K["RSA Private Key<br/>+ key length"]:::report
    BL_V -->|valid| BL_K["BitLocker FVEK"]:::report
    DM_V -->|valid| DM_K["dm-crypt Master Key"]:::report

    classDef source fill:#ffa94d,stroke:#f76707,color:#1a1a2e
    classDef analysis fill:#74c0fc,stroke:#339af0,color:#1a1a2e
    classDef decision fill:#ffd43b,stroke:#f08c00,color:#1a1a2e
    classDef core fill:#868e96,stroke:#495057,color:#fff
    classDef detect fill:#c084fc,stroke:#7950f2,color:#fff
    classDef report fill:#69db7c,stroke:#2f9e44,color:#1a1a2e
```

### Anomaly Scoring

Processes are scored on a 0.0 (normal) to 1.0 (highly anomalous) scale using weighted heuristics:

| Feature | Weight | Threshold |
|:--------|:------:|:----------|
| RWX memory regions | +0.15/region | Max 0.4 |
| Unknown modules | +0.10/module | Max 0.3 |
| Heap entropy | +0.20 | > 7.5 bits/byte |
| Handle count | +0.10 | > 10,000 |

Optional ML scoring via scikit-learn `IsolationForest` can supplement or replace heuristic scoring.

---

## YARA Rule Sets

Deep View ships with curated YARA rule sets for common forensic scenarios:

**`malware.yar`** --- General malware indicators
- Suspicious command strings (`cmd.exe /c`, `/bin/sh -c`, `powershell -enc`)
- Base64-encoded PE files
- Common shellcode byte patterns (NOP sleds, x86/x64 syscall sequences)

**`credentials.yar`** --- Credential material
- PEM-encoded private keys (RSA, EC, OpenSSH)
- AWS access key patterns (`AKIA[0-9A-Z]{16}`)
- Password/API key assignment patterns

**`exploits.yar`** --- Exploit tool indicators
- Process injection API combinations (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`)
- Mimikatz string signatures
- Cobalt Strike Beacon indicators

---

## References

### Core Forensic Frameworks

| Tool | Description | Link |
|:-----|:------------|:-----|
| Volatility 3 | Open-source memory forensics framework | https://github.com/volatilityfoundation/volatility3 |
| MemProcFS | Memory Process File System --- analyze memory dumps as mounted filesystems | https://github.com/ufrisk/MemProcFS |
| Rekall | Memory forensics framework (legacy, read-only support) | https://github.com/google/rekall |
| YARA | Pattern matching for malware researchers | https://github.com/VirusTotal/yara |
| Frida | Dynamic instrumentation toolkit | https://frida.re |
| LIEF | Library to Instrument Executable Formats (PE, ELF, Mach-O) | https://lief-project.github.io |
| Capstone | Disassembly framework | https://www.capstone-engine.org |

### Memory Acquisition Tools

| Tool | Platform | Description | Link |
|:-----|:---------|:------------|:-----|
| LiME | Linux | Linux Memory Extractor kernel module | https://github.com/504ensicsLabs/LiME |
| AVML | Linux | Acquire Volatile Memory for Linux (Microsoft) | https://github.com/microsoft/avml |
| WinPmem | Windows | Windows physical memory acquisition | https://github.com/Velocidex/WinPmem |
| OSXPmem | macOS | macOS physical memory acquisition | https://github.com/google/rekall/tree/master/tools/osx/OSXPmem |
| PCILeech | Hardware | DMA-based memory acquisition via PCIe/Thunderbolt | https://github.com/ufrisk/pcileech |

### Kernel Tracing Technologies

| Technology | Platform | Description | Link |
|:-----------|:---------|:------------|:-----|
| eBPF | Linux | Extended Berkeley Packet Filter for kernel tracing | https://ebpf.io |
| BCC | Linux | BPF Compiler Collection (Python bindings) | https://github.com/iovisor/bcc |
| DTrace | macOS/Solaris | Dynamic tracing framework | https://dtrace.org |
| ETW | Windows | Event Tracing for Windows | https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing |

### Threat Intelligence Standards

| Standard | Description | Link |
|:---------|:------------|:-----|
| STIX 2.1 | Structured Threat Information Expression | https://oasis-open.github.io/cti-documentation/stix/intro.html |
| TAXII 2.1 | Trusted Automated Exchange of Intelligence Information | https://oasis-open.github.io/cti-documentation/taxii/intro.html |
| MITRE ATT&CK | Adversarial Tactics, Techniques, and Common Knowledge | https://attack.mitre.org |
| ATT&CK Navigator | Web app for annotating and exploring ATT&CK matrices | https://mitre-attack.github.io/attack-navigator |
| Sigma | Generic signature format for SIEM systems | https://github.com/SigmaHQ/sigma |

### Symbol and Debug Information

| Tool | Description | Link |
|:-----|:------------|:-----|
| dwarf2json | Convert DWARF debug info to Volatility 3 ISF | https://github.com/volatilityfoundation/dwarf2json |
| Volatility 3 Symbol Tables | Pre-built ISF files for common OS kernels | https://github.com/volatilityfoundation/volatility3#symbol-tables |
| Microsoft Symbol Server | PDB symbols for Windows binaries | https://learn.microsoft.com/en-us/windows/win32/dxtecharts/debugging-with-symbols |

### Virtualization APIs

| API | Description | Link |
|:----|:------------|:-----|
| libvirt | Virtualization management API (QEMU/KVM, Xen) | https://libvirt.org |
| VBoxManage | VirtualBox command-line interface | https://www.virtualbox.org/manual/ch08.html |
| vmrun | VMware Workstation/Fusion CLI | https://docs.vmware.com/en/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-532F4BE3-1E67-4B34-9D7A-6C205DFE8E37.html |
| LibVMI | Virtual Machine Introspection library | https://github.com/libvmi/libvmi |

### Research Papers and Resources

| Title | Authors / Source | Relevance |
|:------|:-----------------|:----------|
| *The Art of Memory Forensics* | Ligh, Case, Levy, Walters (2014) | Definitive reference for Windows/Linux/macOS memory analysis |
| *Volatility 3: The Next Generation of Memory Forensics* | Volatility Foundation | Architecture and plugin design for Volatility 3 |
| *MemProcFS: Memory Process File System* | Ulf Frisk | Filesystem-based approach to memory forensics; scatter-read optimization |
| *DKOM: Direct Kernel Object Manipulation* | Various | Techniques for hiding processes, drivers, and connections in kernel memory |
| *Process Injection Techniques --- Gotta Catch Them All* | Elastic Security | Comprehensive survey of T1055 sub-techniques |
| *BPF Performance Tools* | Brendan Gregg (2019) | eBPF tracing patterns and BCC tooling |
| *Finding Encryption Keys in Memory* | Various forensic researchers | AES key schedule detection, RSA structure identification |
| MITRE ATT&CK for Enterprise | MITRE Corporation | Framework for adversary tactics and techniques | 

### Related Forensic Tools

| Tool | Description | Link |
|:-----|:------------|:-----|
| Plaso / log2timeline | Super timeline creation from multiple log sources | https://github.com/log2timeline/plaso |
| Autopsy / Sleuth Kit | Digital forensics platform (disk forensics) | https://www.sleuthkit.org |
| GRR Rapid Response | Remote live forensics for incident response | https://github.com/google/grr |
| Velociraptor | Endpoint visibility and digital forensics | https://github.com/Velocidex/velociraptor |
| MISP | Malware Information Sharing Platform | https://www.misp-project.org |
| OpenCTI | Open Cyber Threat Intelligence Platform | https://github.com/OpenCTI-Platform/opencti |
| ClamAV | Open-source antivirus engine | https://www.clamav.net |
| FLOSS | FLARE Obfuscated String Solver | https://github.com/mandiant/flare-floss |
| angr | Binary analysis platform (symbolic execution) | https://angr.io |
| PANDA | Platform for Architecture-Neutral Dynamic Analysis | https://github.com/panda-re/panda |
| Ghidra | NSA reverse engineering framework | https://ghidra-sre.org |

---

## Configuration

Deep View reads configuration from `~/.deepview/config.toml`:

```toml
[general]
log_level = "info"
output_format = "table"
plugin_paths = ["~/.deepview/plugins"]

[memory]
default_engine = "volatility"   # or "memprocfs"
symbol_cache_dir = "~/.deepview/symbols"
yara_rules_dir = "~/.deepview/rules"

[memory.acquisition]
default_method = "auto"
compress = true

[tracing]
default_duration = 30
ring_buffer_pages = 64

[reporting]
default_template = "html"
output_dir = "~/.deepview/reports"
```

Environment variables override config file values with the `DEEPVIEW_` prefix (e.g., `DEEPVIEW_LOG_LEVEL=debug`).

---

## License

MIT
