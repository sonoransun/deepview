# Changelog

All notable changes to Deep View are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

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
