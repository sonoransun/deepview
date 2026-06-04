# Changelog

All notable changes to Deep View are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `deepview remote-image ipmi` no longer crashes at construction; the factory was importing `IPMIProvider` (nonexistent) instead of `IPMIMemoryProvider`.
- `RawMemoryLayer` no longer leaks a file descriptor (and no longer raises `AttributeError` from `__del__`) when construction fails part-way — e.g. mmap of an empty dump; the handles are now initialised before the fallible `open`/`mmap`.
- `deepview storage list` keeps each section heading on one line when the table is empty (Rich was wrapping titles wider than the empty box).
- `remote-lime` refusal message now names the `known_hosts` file explicitly.
- Example custom plugin (`examples/09_register_custom_plugin.py`) now returns a `PluginResult` when its target layer is absent instead of letting `LayerError` escape `run()`.
- `LiveProcessLayer.read()` / `is_valid()` no longer raise `AttributeError` — the `_find_region()` method they relied on was missing and is now implemented (binary search over the sorted `/proc/[pid]/maps` regions).
- GPU offload backends (OpenCL + CUDA) now release/free device buffers via `try/finally`, including on kernel failure before the CPU fallback — they were leaked on every PBKDF2 / SHA-512 kernel run.
- `TrampolineGenerator.generate_trampoline` now emits real aarch64 and x86 trampolines (save/restore + hook call + stolen bytes + jump-back); both previously returned empty bytes, which corrupted non-x86_64 binaries during static patching.
- Hibernation parser hardening: empty/truncated `hiberfil` now raises a clean `FormatError` (was a bare mmap `ValueError`); a rejected file no longer leaks the fd+mmap on a failed construction; and a corrupted memory-range table claiming an absurd page count can no longer hang the parser (it falls back to raw pass-through).
- Storage format readers (`jtag_ram`, `vmware_vmem`, `hyperv_vmrs`, `emmc_raw`) convert the `assert self._mmap is not None` guards that protect real mmap I/O into explicit `RuntimeError`s, so reads after `close()` / on an empty backing file fail cleanly under `python -O` instead of `TypeError`-ing on `None`.
- `storage/encodings/swap_layer.py` now rejects negative run offsets/lengths and validates sidecar JSON (clear `ValueError` instead of `KeyError`/`TypeError`); `wkdm.py` validates the section-offset header before the (still-stubbed) full decode. `ntfs_native` no longer hardcodes `is_symlink=False`.
- BCH `(t=1, m=3, data_chunk=1)` — the degenerate BCH(7,4) "tiny" code — now resolves consistently with or without `galois`. The `galois` capacity model rejected its 1-byte/4-bit chunk (`data_chunk=1 byte = 8 bits > k=4`); that exact combination now always uses the built-in tiny codec, so behaviour is identical whether or not the accelerator is installed. (Surfaced by activating `galois`.) The no-`galois` error for other parameters now names the `ecc` extra.
- zram/zswap reads now raise a clear, actionable error ("install deepview[compression]") when a page needs an absent compression codec, instead of a raw `ImportError` surfacing mid-read (new `storage/encodings/_codecs.py`).

### Added
- `deepview.scanning.rules.manager` — `RuleManager` + `_validate_rule_name`, a path-traversal-safe chokepoint for resolving YARA rule names to files under `config.memory.yara_rules_dir`.
- `deepview scan {yara,ioc,rules}` is now wired to `YaraScanner` / `IndicatorEngine` / `RuleManager` (was print-only). `yara` scans files/directories, `ioc` matches a JSON indicator set against target bytes, `rules --list` enumerates the rules directory.
- `deepview report {timeline,export}` are now wired to the reporting backend (was print-only). `timeline` builds from timestamped artifacts; `export` emits a STIX 2.1 bundle, an ATT&CK Navigator layer, or the full JSON report, reconstructing `Detection` objects from the artifact store.
- A factory smoke test constructs every `deepview remote-image` transport selector, guarding against the import-name drift that once shipped a non-existent `IPMIProvider`.
- **Side-channel subsystem (`src/deepview/sidechannel/`)** — rf-SQUID / dc-SQUID magnetometry probes over a *subject under test*. New `SideChannelProbe` interface + `ProbeCapture` (SHA256 chain-of-custody), `DCSquidProbe` / `RFSquidProbe` (lazy DAQ-driver seam) and a hardware-free deterministic `SimulatedSquidProbe`, a `SideChannelManager.from_context` that publishes `SideChannelCapture*` events and records capture artifacts, and numpy/scipy analysis (`power_spectral_density`, `dominant_frequency`, `correlation`, `leakage_snr`). A `deepview sidechannel {probes,capture,analyze}` CLI gates capture behind `--authorization-statement` + `--confirm`. Docs: `docs/architecture/sidechannel.md` (+ diagram); example: `examples/13_squid_capture_simulated.py`. `SideChannelConfig` gains `squid_*` fields.
- `deepview vm {list,snapshot,extract,analyze}` and `deepview instrument {attach,spawn,patch,analyze}` are now wired to `VMManager` / `InstrumentationManager` (were print-only). `AnalysisContext` gains lazy `vm` and `instrumentation` properties.
- Offload `remote` backend implemented (`RemoteWorkerBackend` + a reference worker `serve()`), replacing the `NotImplementedError` stub — a stdlib-only framed-TCP+JSON transport exercised end-to-end by a loopback test. The default backend stays `process`; `remote` registers only when an endpoint is configured.
- gRPC agent transport: `deepview_agent.proto` plus a gRPC client path in `network_agent.py` behind `grpcio`, with the interim framed-TCP path retained as fallback and the public `NetworkAgentProvider` API unchanged.
- ZFS adapter now parses the active uberblock (highest-txg slot, endianness-aware) and exposes `pool_metadata()` for pool identification; `list`/`read` data access remains roadmap.
- Native filesystem adapters (`ext`, `xfs`, `btrfs`, `f2fs`, `apfs`, `ntfs_native`) now populate `FSEntry.target` with the actual symlink target (previously always `None`).
- Container cipher Known-Answer-Tests for the `DecryptedVolumeLayer` modes (XTS-AES, CBC-ESSIV, CBC-plain64, CTR-AES) via `cryptography`-gated round-trips, plus fixes to `_cipher_cascades.py` / `layer.py` TODOs.
- Offload backend selection is now explicit and test-covered: `submit()`/`submit_many()` accept selection hints (capability requirements, `io_bound`→thread, explicit `backend=`) and pick the first registered+available backend whose capabilities cover the job; existing callers are unaffected.
- `ECCResult.__post_init__` now enforces the decoder invariants (`errors_corrected >= 0`; uncorrectable bookkeeping) that every shipped ECC decoder already upholds.
- `tracing/linux/firehose.py` — a pure-Python adaptive sample/drop decision helper (with a visible drop counter) for the eBPF poll firehose. *(Follow-up: wire it into `tracing/providers/ebpf.py`'s poll loop, which was outside this change's lane.)*
- CPU-accelerated extraction is now verified end-to-end: the accelerated decode / ECC / KDF paths (lz4, python-lzo, reedsolo, galois, argon2-cffi) — already wired but previously untested because the libs were absent — now have skip-gated round-trip / known-answer coverage that **runs** when the accelerator is installed and **skips** when it is not. Adds: lz4 / zstd / lzo round-trips for zram **and** zswap; an Argon2id fixed known-answer + reference cross-check + an end-to-end run through the offload engine; BCH t=4/8 and Reed-Solomon injected-error decode; and an explicit accelerated-backend assertion.
- `deepview doctor` annotates each absent accelerator with whether extraction degrades to a pure-Python fallback (`reedsolo`, `galois` t=1) or is unavailable until the extra is installed (`lz4`/`lzo`/`zstd`/`argon2`), each with the exact `pip install 'deepview[…]'` hint.
- Every `AcquisitionResult` from a remote provider (SSH-dd, LiME-remote, TCP, UDP, network-agent, DMA Thunderbolt / PCIe / FireWire) now carries a SHA256 of the bytes that landed on disk. Providers publish a `RemoteAcquisitionProgressEvent` with `stage="hashing"` so the post-stream rehash is visible.
- Local memory providers (LiME, AVML, OSXPmem, WinPmem, `LiveMemoryProvider`) accept an optional `context: AnalysisContext` and publish `MemoryAcquiredEvent` after a successful capture. `MemoryManager._detect_providers` now threads the manager's context through.

### Documentation
- New `docs/guides/recover-artifacts.md` recovery guide: a decision-flow diagram (`docs/diagrams/recovery-flow.svg`) plus a use-case→capability map covering undelete, unallocated/string carving, volatile-memory artifacts, key-from-memory→unlock, ECC/bad-block repair, partition-table reconstruction, and swap/hibernation recovery. Runnable scenario: `examples/14_recover_artifacts_by_carving.py`.
- README adds an "Acquisition implementation status" table that distinguishes wired transports from parser-only formats and planned work; calls out `ipmi` / `amt` as out-of-band telemetry that does not acquire host RAM, the `agent` transport as an interim framed-TCP shim with gRPC planned, and WinRM as not implemented.
- `docs/architecture/remote-acquisition.md` splits the transport catalogue into memory-acquiring vs. out-of-band telemetry, and adds the SHA256 invariant to the fail-secure list.

## [0.2.0] — 2026-04-15

A large, coordinated release that lands four new subsystems alongside the
original memory / tracing / instrumentation / VM stack: a layered storage
and filesystem pipeline, a CPU-and-GPU offload engine, an encrypted
container unlock orchestrator, and a remote memory acquisition suite with
hard authorization gates. The full release also ships a documentation
site, a changelog, contributing + security policies, and an asciinema
workflow for demo recordings.

### Added

#### Storage stack (`src/deepview/storage/`)

- **`StorageManager`** — central wiring of filesystem adapters, FTL
  translators, and ECC decoders. Public entry point is
  `context.storage`. Auto-registers every in-tree adapter at
  construction; dispatch is by name with a best-effort auto-probe
  fallback that tries each registered filesystem's `probe()` in turn.
- **Dump formats** — new format parsers under `storage/formats/`:
  `nand_raw`, `emmc_raw`, `spi_flash`, `jtag_ram`, `gpu_vram`,
  `minidump_full`, `hyperv_vmrs`, `virtualbox_sav`, `vmware_vmem`.
- **ECC codecs** (`storage/ecc/`) — `hamming`, `bch`, `reed_solomon`
  decoders behind a shared `ECCDecoder` interface; `layouts.py`
  describes page + spare geometry presets (MLC 2 KiB / 64 B,
  SLC 512 B / 16 B, etc.).
- **FTL translators** (`storage/ftl/`) — `ubi`, `jffs2`, `mtd`,
  `badblock`, `emmc_hints`, `ufs`, plus a `linearized` passthrough.
  Every translator consumes a raw NAND-like layer and exposes a
  logical block layer to the filesystem adapters above.
- **Encoding layers** (`storage/encodings/`) — `xpress`, `wkdm`,
  `zram_layer`, `zswap_layer`, `swap_layer`, `standby_compression`,
  used for Windows hibernation + compressed-memory forensics.
- **Filesystem adapters** (`storage/filesystems/`) — pure-Python
  `fat_native` and `ntfs_native`; libbde / pyfsapfs / pyfsntfs /
  pyfsxfs / pyfsbtrfs / pyfsf2fs / pyfshfs / pyfsext / pytsk3
  wrappers; a `zfs.py` skeleton that raises `NotImplementedError`
  with an explanatory message.
- **Partition layer** (`storage/partition.py`) — `MBRPartitionTable`
  and `GPTPartitionTable` producing `PartitionLayer` views over a
  backing `DataLayer`.
- **Auto-probe helper** (`storage/auto.py`) — drives the manager's
  probe pipeline end-to-end from a raw layer.
- **Geometry descriptor** (`storage/geometry.py`) — `NANDGeometry`
  dataclass consumed by ECC + FTL adapters.

#### Offload engine (`src/deepview/offload/`)

- **`OffloadEngine`** — lazily constructed as `context.offload`. Auto-
  registers `thread` and `process` backends (always available) at
  `__init__`, and probes `gpu-opencl`, `gpu-cuda`, and `remote` stubs
  so `engine.status()` only lists reachable adapters. Default backend
  is `process` (CPU-bound KDFs).
- **Backends** (`offload/backends/`) — `thread`, `process`,
  `gpu_opencl`, `gpu_cuda`, `remote` under a shared `OffloadBackend`
  ABC.
- **KDF dispatch** (`offload/kdf.py`) — `pbkdf2_sha256`, `argon2id`,
  `sha512_iter`.
- **Event surface** — `OffloadJobSubmittedEvent`,
  `OffloadJobProgressEvent`, `OffloadJobCompletedEvent` published on
  `context.events` so dashboards / replay / classifiers can follow
  every offloaded job.
- **Futures** (`offload/futures.py`) — `OffloadFuture` wraps stdlib
  `concurrent.futures.Future` with a `tag` and a cancellation hook.

#### Container unlock (`src/deepview/storage/containers/`)

- **`UnlockOrchestrator`** — registry-driven auto-unlock pipeline.
  Tries every registered `Unlocker` adapter against a layer, then
  tries master-key candidates (cheap), keyfiles, and finally
  passphrases routed through the offload engine.
- **`KeySource` hierarchy** — `MasterKey`, `Passphrase`, `Keyfile`,
  each with an async `derive(engine, header)` that either returns a
  raw key or requests a KDF job.
- **`DecryptedVolumeLayer`** — composable `DataLayer` that sits on top
  of the encrypted backing layer and transparently decrypts sector-
  aligned reads.
- **Adapters** — `luks.py` (LUKS1 + LUKS2), `bitlocker.py`,
  `filevault2.py`, `veracrypt.py` (which also handles TrueCrypt-mode
  volumes and hidden-volume detection via a trailing-region probe).
  Each module exports an `UNLOCKER` attribute picked up by the
  orchestrator's import-time auto-discovery.
- **Cipher support** — `xts`, `cbc-essiv`, `cbc-plain64`, `ctr` via
  `_cipher_cascades.py`; VeraCrypt-style cipher cascades are handled
  through the same interface.
- **Event surface** — `ContainerUnlockStartedEvent`,
  `ContainerUnlockProgressEvent`, `ContainerUnlockedEvent`,
  `ContainerUnlockFailedEvent`.

#### Remote acquisition (`src/deepview/memory/acquisition/remote/`)

- **`RemoteEndpoint`** — frozen dataclass describing *where* and *how*
  to reach a remote host. Credentials never live inline; the
  dataclass holds environment-variable names and filesystem paths so
  secrets stay out of the attribute tree and out of any downstream
  serialization.
- **`RemoteAcquisitionProvider`** — extends `MemoryAcquisitionProvider`
  with progress-publishing plumbing (`RemoteAcquisitionProgressEvent`)
  and a `transport_name` hook used by the factory.
- **Transports** — `ssh_dd`, `tcp_stream`, `network_agent`,
  `lime_remote`, `dma_thunderbolt`, `dma_pcie`, `dma_firewire`,
  `ipmi`, `intel_amt`, all dispatched via `factory.build_remote_provider`.
- **Safety gates** — every remote-image CLI command requires
  `--confirm` plus `--authorization-statement`; DMA subcommands add a
  `--enable-dma` flag and a root check, and log an IOMMU warning
  before the first read. `AuthorizationError` is the canonical abort
  surface.
- **Event surface** — `RemoteAcquisitionStartedEvent`,
  `RemoteAcquisitionProgressEvent`, `RemoteAcquisitionCompletedEvent`.

#### CLI command groups

- `deepview storage {list,info,wrap,mount}` — manage storage layers,
  probe adapters, wrap NAND dumps with ECC + FTL, open filesystems.
- `deepview filesystem {ls,cat,stat,find}` — inspect a registered
  filesystem layer.
- `deepview unlock {luks,auto,veracrypt,truecrypt}` — pure-Python +
  libbde-backed unlock pipeline.
- `deepview unlock-native {bitlocker,filevault}` — native-adapter path
  that defers to libbde / libfvde.
- `deepview offload {status,run,benchmark}` — inspect backends, submit
  ad-hoc jobs, compare KDF throughput.
- `deepview remote-image {ssh,tcp,agent,lime,ipmi,amt,dma-tb,dma-pcie,dma-fw}`
  — every remote transport behind an authorization-gated subcommand.

#### Built-in plugins

- New `@register_plugin` built-ins for storage probes, container
  detection, offload-job smoke tests, and remote-acquisition dry
  runs. All are reachable from `plugins/builtin/__init__.py`.

#### Optional-dependency extras (declared in `pyproject.toml`)

- `storage` — `pytsk3`, `pyfsapfs`, `pyfsntfs`, `pyfsxfs`,
  `pyfsbtrfs`, `pyfsf2fs`, `pyfshfs`, `pyfsext`.
- `compression` — `zstandard`, `lz4`, `python-lzo`.
- `ecc` — `reedsolo`, `galois`.
- `offload_gpu` — `pyopencl`, `pycuda`.
- `containers` — `cryptography`, `argon2-cffi`, `pycryptsetup`
  (Linux), `libbde-python`, `libfvde-python`.
- `remote_acquisition` — `paramiko`, `grpcio`, `grpcio-tools`,
  `python-ipmi`, `forensic1394`.
- `docs` — `mkdocs`, `mkdocs-material`, `mkdocs-mermaid2-plugin`,
  `pymdown-extensions`, `mkdocs-asciinema-player-plugin`.
- The `all` aggregator pulls in every new extra.

#### Events (`src/deepview/core/events.py`)

Ten new typed event classes:

- `ContainerUnlockStartedEvent`
- `ContainerUnlockProgressEvent`
- `ContainerUnlockedEvent`
- `ContainerUnlockFailedEvent`
- `RemoteAcquisitionStartedEvent`
- `RemoteAcquisitionProgressEvent`
- `RemoteAcquisitionCompletedEvent`
- `OffloadJobSubmittedEvent`
- `OffloadJobProgressEvent`
- `OffloadJobCompletedEvent`

#### Configuration

- New `DeepViewConfig` subtrees: `storage`, `offload`, `containers`,
  `remote_acquisition`. Each follows the `DEEPVIEW_<SECTION>_<FIELD>`
  env-var override convention.

#### Documentation

- MkDocs-Material site under `docs/` with navigation covering
  overview, architecture, guides, and reference pages.
- Twenty canonical mermaid diagrams under `docs/diagrams/sources/`.
- Three hand-authored CSS-keyframe animated SVGs under
  `docs/diagrams/animated/`.
- Asciinema scenario script `docs/casts/make-casts.sh` (operators
  record locally; CI never re-records).
- New top-level policy files: `CHANGELOG.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SECURITY.md`.

### Changed

- Memory dump format auto-detection now recognises MDMP (full
  minidump), `hibr*` / `wake` (hibernation), SSM (Hyper-V saved
  state), and `.vmem` sidecars. The fallback path consults the file
  extension when the magic bytes are ambiguous.
- `DumpFormat` enum extended with `HIBERFIL`, `MINIDUMP_FULL`,
  `VMWARE_VMEM`, `VIRTUALBOX_SAV`, and `HYPERV_VMRS`.
- `AnalysisContext` gains four new lazy attributes: `offload`,
  `storage`, `unlocker`, `remote`. Each is constructed on first
  access and cached; the existing `layers`, `events`, `plugins`
  attributes keep their original semantics.
- `README.md` overhaul — four new subsystems added to the top-level
  architecture diagram, capability matrices, and asciinema-driven
  60-second tour.
- `CLAUDE.md` extended with per-subsystem directory maps and event-
  class / CLI / extras reference sections.

### Fixed

- Hibernation parser now actually decompresses Xpress-compressed page
  runs (previously a header-only stub).
- Crashdump parser now handles the `BITMAP_DUMP` variant used by
  modern Windows kernels (previously raised on the bitmap header).
- Format detection no longer misclassifies zero-padded raw images as
  ELF cores.

## [0.1.0] — initial release

- Original Deep View toolkit: memory forensics (Volatility 3,
  MemProcFS, page-table reconstruction), tracing (eBPF / DTrace /
  ETW), Frida + static-binary instrumentation, VM introspection, YARA
  scanning, anti-forensics / injection / encryption-key detection,
  anomaly scoring, reporting (HTML, Markdown, JSON, STIX 2.1,
  ATT&CK Navigator).
- Dashboard subsystem (`deepview dashboard run`) with Rich multi-
  panel layout and NFQUEUE-backed packet mangling engine.
- Session replay (`deepview replay`), event classification pipeline,
  and live inspection primitives (`deepview inspect`).
