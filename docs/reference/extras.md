# Optional Dependencies (Extras) Reference

Deep View installs as a small core (`click`, `rich`, `pydantic`,
`pydantic-settings`, `structlog`, `platformdirs`, `pyyaml`) plus a large
set of opt-in extras declared under
`[project.optional-dependencies]` in `pyproject.toml`.

Every heavy dep is an extra because the project is genuinely cross-platform
and every backend fails cleanly when its Python package is missing — `deepview
doctor` reports each backend individually and CLI subcommands that need a
missing extra print a yellow install-hint instead of blowing up.

## Extras catalog

| Extra | Packages | Enables |
|-------|----------|---------|
| `memory` | `volatility3>=2.5`, `yara-python>=4.3` | Memory image analysis via `deepview memory analyze`, YARA scanning. |
| `tracing` | *(reserved; no packages today)* | Reserved — Linux live tracing pulls `linux_monitoring` instead. |
| `linux_monitoring` | `bcc>=0.29`, `pyroute2>=0.7`, `psutil>=5.9`, `netfilterqueue>=1.1` | Live eBPF tracing, netlink inspection, NFQUEUE packet mangling. |
| `instrumentation` | `frida>=16.0`, `lief>=0.14`, `capstone>=5.0` | Frida dynamic instrumentation + LIEF/Capstone static binary patching. |
| `vm` | *(reserved)* | VM-connector extra; shipped connectors today use system tools (`virsh`, `vboxmanage`, `vmrun`). |
| `detection` | `pyattck>=7.1`, `stix2>=3.0` | ATT&CK Navigator layer export + STIX 2.1 bundles. |
| `hardware` | `leechcore>=2.0` | DMA acquisition via LeechCore. |
| `firmware` | `chipsec>=1.10`, `uefi-firmware>=1.9` | UEFI / SPI firmware analysis. |
| `gpu` | `pycuda>=2022.1`, `pyopencl>=2022.1` | GPU-accelerated detection (`detection/*`), YARA-GPU. |
| `ml` | `scikit-learn>=1.3`, `xgboost>=2.0` | ML-driven anomaly scoring (`detection/anomaly.py`). |
| `sigma` | `pyyaml>=6.0` | Sigma-rule conversion for the classifier. |
| `sidechannel` | `numpy>=1.24`, `scipy>=1.10` | SDR / ChipWhisperer side-channel pipelines. |
| `disassembly` | `capstone>=5.0`, `pyhidra>=1.0` | `deepview disassemble` (Capstone + Ghidra via pyhidra). |
| `storage` | `pytsk3`, `pyfsapfs`, `pyfsntfs`, `pyfsxfs`, `pyfsbtrfs`, `pyfsf2fs`, `pyfshfs`, `pyfsext` | Full native + TSK filesystem adapter stack for `deepview filesystem`, `storage`. |
| `compression` | `zstandard>=0.22`, `lz4>=4.3`, `python-lzo>=1.15` | Swap / zram / zswap / filesystem-compression decoders. |
| `ecc` | `reedsolo>=1.7`, `galois>=0.3` | Reed-Solomon + BCH accelerators for NAND ECC decoding. |
| `offload_gpu` | `pyopencl>=2022.1`, `pycuda>=2022.1` | Offload engine GPU backends (`OpenCLBackend`, `CUDABackend`). |
| `containers` | `cryptography>=41.0`, `argon2-cffi>=23.1`, `pycryptsetup>=0.2` (Linux), `libbde-python`, `libfvde-python` | `deepview unlock` (LUKS / VeraCrypt / BitLocker / FileVault 2). |
| `remote_acquisition` | `paramiko>=3.3`, `grpcio>=1.58`, `grpcio-tools>=1.58`, `python-ipmi>=0.5`, `forensic1394>=0.3` | `deepview remote-image` transports. |
| `docs` | `mkdocs`, `mkdocs-material`, `mkdocs-mermaid2-plugin`, `pymdown-extensions`, `mkdocs-asciinema-player-plugin` | Build this documentation site. |
| `all` | Every extra above | Convenience meta-extra. |
| `dev` | `pytest`, `pytest-cov`, `pytest-asyncio`, `pytest-mock`, `mypy`, `ruff` | Test & lint tooling. |

## Doctor reporting

`deepview doctor` (see `cli/app.py`) probes each optional package via
`__import__` or `shutil.which` and prints `✓` / `✗`. A complete report for a
minimal install contains four sections:

1. **Platform** — OS, arch, kernel, capability flags.
2. **External tools** — `volatility3`, `frida`, `yara`, `lief`, `dtrace`,
   `vboxmanage`, `vmrun`, `virsh`.
3. **Storage backends** — `pytsk3`, `pyfsapfs`, `pyfsntfs`, `pyfsxfs`,
   `pyfsbtrfs`, `pyfsf2fs`, `pyfshfs`, `pyfsext`, `zstandard`, `lz4`, `lzo`,
   `reedsolo`, `galois`, `cryptography`, `argon2`, `paramiko`, `grpc`.
4. No additional section is specific to tracing today — the `linux_monitoring`
   extras (`bcc`, `pyroute2`, `psutil`, `netfilterqueue`) are not probed as of
   this writing; run `python -c "import bcc"` separately if you need to check.

Every module reported red (`✗`) corresponds to a subcommand / backend that
will refuse to operate with a yellow install-hint rather than traceback.

## Graceful-degradation matrix

| Subcommand | Needs | Without the extra |
|------------|-------|-------------------|
| `deepview memory acquire` | (none at the CLI surface; providers vary) | Prints a "platform-specific tools" note. |
| `deepview memory analyze` | `memory` | `MemoryManager` raises, CLI prints red error and `SystemExit(1)`. |
| `deepview memory scan` | `memory` | Prints yellow `pip install deepview[memory]` hint. |
| `deepview vm {list,snapshot,extract,analyze}` | `vm` + system tools | Prints yellow hypervisor-required hint. |
| `deepview trace *` | `linux_monitoring` | `TraceManager.start()` raises `MonitorError("eBPF backend unavailable: bcc not installed")`; CLI prints red. |
| `deepview instrument *` | `instrumentation` | Prints yellow `pip install deepview[instrumentation]` hint. |
| `deepview scan {yara,ioc}` | `memory` | Prints yellow install hint. |
| `deepview disassemble *` | `disassembly` | `DisassemblyManager` raises with the engine name; CLI prints red. |
| `deepview replay {record,play}` | `linux_monitoring` (for record), core only for replay | Record fails with `MonitorError`; replay works with any stored DB. |
| `deepview inspect *` | core on Linux; stdlib-only `procfs` | Works on a bare install; YARA needs the `memory` extra. |
| `deepview monitor *` | `linux_monitoring` | Same as `trace`. |
| `deepview dashboard run --enable-mangle` | `linux_monitoring` (`netfilterqueue`) | `NFQueueSource` raises `BackendNotAvailableError`; CLI prints red. |
| `deepview netmangle run` | `linux_monitoring` (`netfilterqueue`) | Same as above. |
| `deepview offload status` | core | Always works; `OpenCLBackend` / `CUDABackend` report `available=False`. |
| `deepview offload run --backend gpu-*` | `offload_gpu` (+ `config.offload.gpu_enabled=true`) | Backend rejects the submit; falls back if `--backend` is unset. |
| `deepview remote-image ssh` | `remote_acquisition` (`paramiko`) | Provider factory raises `BackendNotAvailableError`. |
| `deepview remote-image agent` | `remote_acquisition` (`grpcio`) | Same as above. |
| `deepview remote-image ipmi` | `remote_acquisition` (`python-ipmi`) | Same. |
| `deepview remote-image dma-*` | `remote_acquisition` (`forensic1394` for firewire) + `hardware` | Same, plus `--enable-dma` gate. |
| `deepview storage info/wrap/mount/list` | `storage` | `storage list` always works (shows empty tables); `storage mount` + filesystem ops need at least one adapter installed — TSK (`pytsk3`) or a native pyfs* backend. |
| `deepview storage wrap --ecc ...` | `ecc` | Wrap silently skips ECC with a yellow warning; the resulting layer bypasses the decoder. |
| `deepview storage wrap --ftl ...` | (no additional extra; FTL is pure-Python) | Always works. |
| `deepview filesystem ls/cat/stat/find` | `storage` (one filesystem adapter sufficient) | `StorageError` bubbles up to a red CLI message. |
| `deepview unlock luks` | `containers` (`cryptography`, `pycryptsetup` on Linux) | Raises; CLI prints red. |
| `deepview unlock veracrypt` / `truecrypt` | `containers` (`cryptography`, `argon2-cffi`) | Same as above. |
| `deepview unlock auto --memory-dump` | `containers` + in-process memory layer | Works without `containers` for detection; unlock attempts fail without it. |
| `deepview unlock-native bitlocker` | `containers` (`libbde-python`) | Raises on `detect()` with missing backend. |
| `deepview unlock-native filevault` | `containers` (`libfvde-python`) | Same. |

## Bundling guidance

- **Bare install** (`pip install deepview`): core CLI, `doctor`, `plugins`,
  inspection, classification replay, offload CPU backends, partial trace
  (tracepoint enumeration without live capture).
- **Live forensic workstation** (`pip install 'deepview[storage,containers,
  compression,ecc,remote_acquisition,memory,instrumentation,
  linux_monitoring]'`): every CLI surface operational.
- **Headless agent**: `pip install 'deepview[linux_monitoring,
  remote_acquisition]'` for the minimum trace + remote-image footprint.
- **Full kitchen-sink**: `pip install 'deepview[all,dev]'` — every extra
  plus the test/lint tooling.

## Per-extra installation recipes

### `memory`

```bash
pip install 'deepview[memory]'
```

Unlocks `deepview memory analyze / scan` and every memory-image-backed
plugin (`pslist`, `netstat`, `malfind`, `timeliner`, `dkom_detect`,
`credentials`, `pagetable_walk`, `strings`, `command_history`,
`extracted_keys`). Volatility 3 is used as a library, not a subprocess —
the engine imports `volatility3` directly.

### `linux_monitoring`

```bash
pip install 'deepview[linux_monitoring]'
```

Note: `bcc` generally requires matching kernel headers + a distro package
(`linux-headers-$(uname -r)`, `libbpfcc-dev`). The optional
`netfilterqueue` package requires `libnetfilter-queue-dev`.

### `instrumentation`

```bash
pip install 'deepview[instrumentation]'
```

Frida ships prebuilt wheels for the major platforms. LIEF + Capstone are
pure-Python wheels. Binary patching is a static-reassembly pipeline in
`instrumentation/binary/`.

### `disassembly`

```bash
pip install 'deepview[disassembly]'
```

`pyhidra` requires a pre-installed Ghidra (set via
`config.disassembly.ghidra_install_dir` or env). Capstone is optional but
recommended — it's the fallback engine when neither Ghidra nor Hopper is
present.

### `storage`

```bash
pip install 'deepview[storage]'
```

`pytsk3` acts as the fallback for formats without a native pyfs* adapter.
Set `config.storage.prefer_native_filesystems = True` (default) to prefer
the native adapter when both are installed.

### `containers`

```bash
pip install 'deepview[containers]'
```

`pycryptsetup` is Linux-only (marker `platform_system=='Linux'`), so
BitLocker/FileVault adapters work on any OS but `deepview unlock luks`
needs a Linux host with cryptsetup installed.

### `remote_acquisition`

```bash
pip install 'deepview[remote_acquisition]'
```

`forensic1394` requires `libforensic1394-dev` on Linux; `python-ipmi`
requires no system package.

### `ecc` + `compression`

```bash
pip install 'deepview[ecc,compression]'
```

Accelerates NAND ECC decoding (BCH via `galois`, Reed-Solomon via
`reedsolo`) and decompresses swap / zram / zswap / filesystem chunks.
Without `compression`, only uncompressed pages are readable; without `ecc`,
NAND pages pass through without correction and uncorrectable markers
accumulate in the result metadata.

### `offload_gpu`

```bash
pip install 'deepview[offload_gpu]'
```

GPU backends remain opt-in at runtime via `config.offload.gpu_enabled =
true`. `pycuda` requires CUDA toolkit + compatible driver; `pyopencl`
requires an OpenCL ICD.

### `gpu`

```bash
pip install 'deepview[gpu]'
```

Same pair as `offload_gpu` but reserved for detection code paths
(`detection/*` GPU-accelerated YARA, entropy scoring). Kept as a separate
extra in `pyproject.toml` so installing one does not implicitly pull in the
other's runtime surface.

### `detection`, `ml`, `sigma`, `sidechannel`, `firmware`, `hardware`

Smaller specialty extras:

- `detection`: `pyattck` + `stix2` for the report engine's ATT&CK /
  STIX export.
- `ml`: `scikit-learn` + `xgboost` for `detection/anomaly.py`.
- `sigma`: `pyyaml` (already core) — reserved for future Sigma rule
  import paths.
- `sidechannel`: `numpy` + `scipy` for SDR / ChipWhisperer pipelines.
- `firmware`: `chipsec` + `uefi-firmware` for UEFI / SPI analysis.
- `hardware`: `leechcore` for DMA acquisition via LeechCore.

### `docs`

```bash
pip install 'deepview[docs]'
mkdocs serve
```

Everything this documentation site is built with.

### `dev`

```bash
pip install 'deepview[dev]'
pytest
ruff check src tests
mypy src
```

Test + lint tooling. Strict `mypy` is configured in `pyproject.toml`;
`ruff` targets py310, line-length 100.

## Tip: matching `deepview doctor` output

If you've just run `deepview doctor` and see a row of red `✗`, map each name
to the extra that provides it:

| Missing module | Install with |
|----------------|--------------|
| `volatility3`, `yara` | `pip install 'deepview[memory]'` |
| `frida`, `lief` | `pip install 'deepview[instrumentation]'` |
| `pytsk3`, `pyfs*` | `pip install 'deepview[storage]'` |
| `zstandard`, `lz4`, `lzo` | `pip install 'deepview[compression]'` |
| `reedsolo`, `galois` | `pip install 'deepview[ecc]'` |
| `cryptography`, `argon2` | `pip install 'deepview[containers]'` |
| `paramiko`, `grpc` | `pip install 'deepview[remote_acquisition]'` |
| `dtrace` / `vboxmanage` / `vmrun` / `virsh` | system packages — install via OS package manager. |

## Cross-references

- `deepview doctor` output is described in [cli.md](cli.md#deepview-doctor).
- Config fields that gate optional behavior:
  [config.md](config.md#offloadconfig) (`gpu_enabled`),
  [config.md](config.md#containersconfig) (`allow_write`),
  [config.md](config.md#networkmangleconfig) (`fail_open`).
- Concrete backends behind each extra: [interfaces.md](interfaces.md).
