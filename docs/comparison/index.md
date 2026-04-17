# Tool Comparison Landscape

!!! abstract "Deep View overlaps with multiple existing tools by design — it's a coordinator, not a replacement."
    Deep View sits at a layer above the canonical forensics, DFIR, and reverse-engineering tools.
    It does not re-implement what Volatility 3, The Sleuth Kit, Frida, or rr already do well. Instead
    it imports them as libraries where possible, drives them through a uniform `AnalysisContext`, and
    pushes their findings into a single `EventBus` for classification, replay, and reporting.

If you already own a workflow built around one of these tools, Deep View is most useful as the
layer that *glues* them together — not as a rewrite of the tool itself.

## The landscape at a glance

The table below is deliberately honest: every tool listed here has at least one dimension where it
is the authoritative choice and Deep View is not. The point of this section is to tell you when to
reach for the underlying tool directly and when the coordination Deep View provides earns its keep.

| Tool | Domain | Overlap with Deep View | Distinguishing strength | Distinguishing limitation |
| --- | --- | --- | --- | --- |
| [Volatility 3](volatility.md) | Memory forensics plugins | Deep View calls vol3 as a library for memory analysis | Largest curated plugin ecosystem for memory images | Image-only; no live tracing, no classification pipeline |
| [Autopsy / TSK](autopsy.md) | Disk and filesystem forensics | Deep View uses TSK bindings for filesystem surfaces | Rich GUI, mature case management, keyword indexing | GUI-first; automation via REST is secondary |
| [Velociraptor](velociraptor.md) | Distributed live-IR | Deep View and Velociraptor both do live tracing + rules | Fleet-scale agent-server model, VQL query language | Server infrastructure required; not a single-host tool |
| [Frida](frida-standalone.md) | Dynamic instrumentation | Deep View wraps Frida via `instrumentation/frida_engine.py` | The reference implementation for cross-platform DBI | No classification, no session replay, no reporting |
| [GDB + rr](gdb-rr.md) | Record/replay debugging | Deep View replays events; rr replays instructions | Deterministic per-instruction replay, reverse-execution | Per-process, x86 Linux only, huge trace files |
| [LiME](#lime-linux-memory-extractor) | Linux memory acquisition | Deep View invokes LiME via `memory/acquisition/lime.py` | Kernel-module acquisition with format choice | Linux-only; acquisition only, no analysis |
| [PCILeech](#pcileech) | Hardware-assisted DMA acquisition | Deep View drives PCILeech via the hardware subsystem | True out-of-band memory access over PCIe/USB-C | Requires specific hardware (FPGA, USB3380, etc.) |
| [Cryptsetup / LUKS tools](#cryptsetup) | Full-disk decryption | Deep View uses cryptsetup bindings for LUKS containers | Canonical LUKS implementation | Interactive; not geared toward offline forensic chaining |
| [Dislocker](#dislocker) | BitLocker decryption | Deep View shells out to dislocker for encrypted volumes | Mature BitLocker support | CLI-first; limited programmatic surface |
| [YARA](#yara) | Pattern matching engine | Deep View uses `yara-python` in `scanning/` | The reference signature language for malware | Pattern-only; no behavioural tracing |

## How to read the rest of this section

Each subpage follows the same template:

- **What the other tool is** in one paragraph.
- **Where Deep View overlaps** — the specific module or CLI surface that touches it.
- **Where Deep View does NOT overlap** — the honest list of features that belong to the other tool.
- **When to use each** — a concrete decision rubric.
- **How to combine them** — what the integration looks like in practice.

If you are comparing Deep View against a tool not listed here, two good starting points are the
[architecture overview](../architecture/tracing-and-classification.md) and the
[plugin system](../architecture/containers.md) — most integrations ultimately reduce to either
"wrap it as a plugin" or "feed its output onto the EventBus".

## Short notes on tools that don't warrant their own page

### LiME (Linux Memory Extractor) { #lime-linux-memory-extractor }

LiME is the canonical kernel module for dumping volatile memory on Linux. Deep View invokes it
through `deepview.memory.acquisition.lime` and simply parses the resulting image via
`memory/formats/lime_format.py`. Use LiME directly when you only need acquisition and do not want
the Python toolchain. Use Deep View when the acquisition is step one in a longer pipeline.

### PCILeech { #pcileech }

PCILeech is Ulf Frisk's DMA acquisition framework — it reaches across PCIe to read memory from a
live system without any cooperation from the target OS. Deep View's `hardware/` subsystem wraps
the `leechcore` library to drive PCILeech from the CLI. PCILeech standalone remains the right
choice when you want its native TUI, kernel-module injection, or arbitrary read/write experiments.

### Cryptsetup / LUKS tooling { #cryptsetup }

Cryptsetup is the canonical userspace for LUKS containers. Deep View's acquisition layer asks
cryptsetup to unlock a container so later passes can analyse the decrypted device. If you already
have the keys and a shell, cryptsetup alone is simpler. Deep View adds value when an LUKS volume
is one of many surfaces being acquired in an automated pipeline.

### Dislocker { #dislocker }

Dislocker is the go-to for reading BitLocker volumes from a non-Windows host. Deep View treats it
as an external dependency — the acquisition module knows how to unlock a volume and then hand it
to a layer. There's no competitive overlap here; we just try to keep the invocation tidy.

### YARA { #yara }

YARA is in a slightly different category: it's a library, not a tool-with-a-workflow. Deep View's
`scanning/yara_engine.py` embeds `yara-python` directly, exposes the same rule-compilation surface,
and runs rules over `DataLayer` instances (memory images, live `/proc/[pid]/mem`, disk, etc.). If
you're already writing YARA rules, nothing in Deep View replaces that — we just offer more places
to run them.

## Guiding principle

!!! tip "Coordinator, not a rewrite"
    When in doubt: if the other tool *is* the source of authority for its domain (Volatility for
    memory plugins, rr for deterministic replay, Frida for DBI), Deep View's role is to invoke it
    and integrate its output — not to replicate it. When you find a case where Deep View *should*
    defer to an external tool but isn't, that's a bug worth filing.

## Next

- [Volatility 3](volatility.md) — how the memory plugin bridge works.
- [Autopsy / TSK](autopsy.md) — programmatic vs GUI filesystem forensics.
- [Velociraptor](velociraptor.md) — fleet-scale live IR vs single-host toolkit.
- [Frida standalone](frida-standalone.md) — instrumentation framework vs integration layer.
- [GDB + rr](gdb-rr.md) — instruction-level determinism vs event-level replay.
