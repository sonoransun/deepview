# Configuration Reference

`DeepViewConfig` (`src/deepview/core/config.py`) is a `pydantic-settings`
root that composes nineteen sub-configs. It loads from
`~/.config/deepview/config.toml` (or the path passed to `--config`) and
supports environment-variable overrides via the `DEEPVIEW_` prefix.

This page documents every sub-config's fields, their defaults, and the env
var that overrides each. All paths are resolved via `platformdirs` — on
Linux, `XDG_CONFIG_HOME`/`XDG_CACHE_HOME` apply.

## Root (`DeepViewConfig`)

Env prefix: `DEEPVIEW_`.

| Field | Type | Default | Env var | Description |
|-------|------|---------|---------|-------------|
| `log_level` | str | `"info"` | `DEEPVIEW_LOG_LEVEL` | `debug`/`info`/`warning`/`error`. |
| `output_format` | str | `"table"` | `DEEPVIEW_OUTPUT_FORMAT` | `table`/`json`/`csv`/`timeline`. |
| `plugin_paths` | list[str] | `[]` | `DEEPVIEW_PLUGIN_PATHS` (JSON) | Extra plugin search paths. |
| `config_dir` | Path | `user_config_dir("deepview")` | `DEEPVIEW_CONFIG_DIR` | Root for ruleset / layout files. |
| `cache_dir` | Path | `user_cache_dir("deepview")` | `DEEPVIEW_CACHE_DIR` | Root for session DBs, mangle state, symbol cache. |
| `memory` | `MemoryConfig` | defaults | `DEEPVIEW_MEMORY__*` | See below. |
| `acquisition` | `AcquisitionConfig` | defaults | `DEEPVIEW_ACQUISITION__*` | – |
| `vm` | `VMConfig` | defaults | `DEEPVIEW_VM__*` | – |
| `tracing` | `TracingConfig` | defaults | `DEEPVIEW_TRACING__*` | – |
| `instrumentation` | `InstrumentationConfig` | defaults | `DEEPVIEW_INSTRUMENTATION__*` | – |
| `reporting` | `ReportingConfig` | defaults | `DEEPVIEW_REPORTING__*` | – |
| `hardware` | `HardwareConfig` | defaults | `DEEPVIEW_HARDWARE__*` | – |
| `firmware` | `FirmwareConfig` | defaults | `DEEPVIEW_FIRMWARE__*` | – |
| `gpu` | `GPUConfig` | defaults | `DEEPVIEW_GPU__*` | – |
| `sidechannel` | `SideChannelConfig` | defaults | `DEEPVIEW_SIDECHANNEL__*` | – |
| `disassembly` | `DisassemblyConfig` | defaults | `DEEPVIEW_DISASSEMBLY__*` | – |
| `classification` | `ClassificationConfig` | defaults | `DEEPVIEW_CLASSIFICATION__*` | – |
| `replay` | `ReplayConfig` | defaults | `DEEPVIEW_REPLAY__*` | – |
| `monitor` | `MonitorConfig` | defaults | `DEEPVIEW_MONITOR__*` | – |
| `dashboard` | `DashboardConfig` | defaults | `DEEPVIEW_DASHBOARD__*` | – |
| `network_mangle` | `NetworkMangleConfig` | defaults | `DEEPVIEW_NETWORK_MANGLE__*` | – |
| `storage` | `StorageConfig` | defaults | `DEEPVIEW_STORAGE__*` | – |
| `containers` | `ContainersConfig` | defaults | `DEEPVIEW_CONTAINERS__*` | – |
| `offload` | `OffloadConfig` | defaults | `DEEPVIEW_OFFLOAD__*` | – |
| `remote_endpoints` | list[`RemoteEndpointConfig`] | `[]` | `DEEPVIEW_REMOTE_ENDPOINTS` (JSON) | Declarative remote hosts. |

### Config-loading security checks

`DeepViewConfig.load()` (see `core/config.py`) runs `_validate_config_file`
before parsing TOML. The checks, in order:

1. **Symlink rejection** — if `path.is_symlink()` the loader raises
   `ConfigError("Config file is a symlink (rejected): ...")`. This blocks
   symlink-attack vectors where a world-writable directory points at a
   sensitive file.
2. **Regular-file check** — the resolved path must be a file, not a
   directory / device / pipe.
3. **Size limit** — the file must be ≤ 10 MiB (`_MAX_CONFIG_SIZE`). A
   larger file yields `ConfigError("Config file too large ...")`.
4. **TOML decode errors** — wrapped in `ConfigError` with the inner
   message.
5. **Pydantic validation** — wrapped in
   `ConfigError("Invalid configuration in {path}: ...")`.

**Do not bypass these checks** when adding new config loaders — they exist
because `--config` accepts any path the user provides and the application
must not follow a dangling / untrusted symlink.

### CLI override precedence

Precedence (highest → lowest):

1. CLI flag (`--output-format`, `--log-level`, `--plugin-path`, ...).
2. Env var (`DEEPVIEW_OUTPUT_FORMAT`, `DEEPVIEW_LOG_LEVEL`, ...).
3. `--config PATH` contents.
4. `~/.config/deepview/config.toml` contents.
5. Sub-config field defaults in `core/config.py`.

The CLI layer in `cli/app.py::main` explicitly overwrites `config.output_format`
and prepends `--plugin-path` entries to `config.plugin_paths`.

## `MemoryConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_engine` | str | `"volatility"` | `DEEPVIEW_MEMORY__DEFAULT_ENGINE` |
| `symbol_cache_dir` | Path | `user_cache_dir/symbols` | `DEEPVIEW_MEMORY__SYMBOL_CACHE_DIR` |
| `yara_rules_dir` | Path | `user_config_dir/rules` | `DEEPVIEW_MEMORY__YARA_RULES_DIR` |

```toml
[memory]
default_engine = "volatility"
symbol_cache_dir = "/var/cache/deepview/symbols"
```

```bash
DEEPVIEW_MEMORY__DEFAULT_ENGINE=memprocfs deepview doctor
```

## `AcquisitionConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_method` | str | `"auto"` | `DEEPVIEW_ACQUISITION__DEFAULT_METHOD` |
| `compress` | bool | `True` | `DEEPVIEW_ACQUISITION__COMPRESS` |

```toml
[acquisition]
default_method = "lime"
compress = false
```

## `VMConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_hypervisor` | str | `"auto"` | `DEEPVIEW_VM__DEFAULT_HYPERVISOR` |
| `libvirt_uri` | str | `"qemu:///system"` | `DEEPVIEW_VM__LIBVIRT_URI` |

```toml
[vm]
default_hypervisor = "vbox"
libvirt_uri = "qemu+ssh://root@host/system"
```

## `TracingConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_duration` | int | `30` | `DEEPVIEW_TRACING__DEFAULT_DURATION` |
| `ring_buffer_pages` | int | `64` | `DEEPVIEW_TRACING__RING_BUFFER_PAGES` |

```toml
[tracing]
default_duration = 120
ring_buffer_pages = 256
```

## `InstrumentationConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `frida_server_path` | str | `""` | `DEEPVIEW_INSTRUMENTATION__FRIDA_SERVER_PATH` |

```toml
[instrumentation]
frida_server_path = "/usr/local/bin/frida-server"
```

## `ReportingConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_template` | str | `"html"` | `DEEPVIEW_REPORTING__DEFAULT_TEMPLATE` |
| `output_dir` | Path | `user_config_dir/reports` | `DEEPVIEW_REPORTING__OUTPUT_DIR` |

## `HardwareConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `dma_backend` | str | `"auto"` | `DEEPVIEW_HARDWARE__DMA_BACKEND` |
| `pcileech_device` | str | `""` | `DEEPVIEW_HARDWARE__PCILEECH_DEVICE` |
| `cold_boot_temperature_c` | float | `-50.0` | `DEEPVIEW_HARDWARE__COLD_BOOT_TEMPERATURE_C` |
| `cold_boot_elapsed_s` | float | `0.0` | `DEEPVIEW_HARDWARE__COLD_BOOT_ELAPSED_S` |

```toml
[hardware]
dma_backend = "pcileech"
pcileech_device = "fpga"
```

## `FirmwareConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `spi_backend` | str | `"auto"` | `DEEPVIEW_FIRMWARE__SPI_BACKEND` |
| `chipsec_modules` | list[str] | `[]` | `DEEPVIEW_FIRMWARE__CHIPSEC_MODULES` |
| `known_good_firmware_db` | str | `""` | `DEEPVIEW_FIRMWARE__KNOWN_GOOD_FIRMWARE_DB` |

## `GPUConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `backend` | str | `"auto"` | `DEEPVIEW_GPU__BACKEND` |
| `cuda_device_id` | int | `0` | `DEEPVIEW_GPU__CUDA_DEVICE_ID` |

## `SideChannelConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `sdr_device` | str | `""` | `DEEPVIEW_SIDECHANNEL__SDR_DEVICE` |
| `chipwhisperer_serial` | str | `""` | `DEEPVIEW_SIDECHANNEL__CHIPWHISPERER_SERIAL` |
| `sample_rate_hz` | int | `20_000_000` | `DEEPVIEW_SIDECHANNEL__SAMPLE_RATE_HZ` |

## `DisassemblyConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_engine` | str | `"auto"` | `DEEPVIEW_DISASSEMBLY__DEFAULT_ENGINE` |
| `ghidra_install_dir` | str | `""` | `DEEPVIEW_DISASSEMBLY__GHIDRA_INSTALL_DIR` |
| `ghidra_project_dir` | str | `""` | `DEEPVIEW_DISASSEMBLY__GHIDRA_PROJECT_DIR` |
| `ghidra_jvm_args` | list[str] | `["-Xmx4g"]` | `DEEPVIEW_DISASSEMBLY__GHIDRA_JVM_ARGS` |
| `ghidra_analysis_timeout` | int | `600` | `DEEPVIEW_DISASSEMBLY__GHIDRA_ANALYSIS_TIMEOUT` |
| `hopper_cli_path` | str | `""` | `DEEPVIEW_DISASSEMBLY__HOPPER_CLI_PATH` |
| `hopper_license_path` | str | `""` | `DEEPVIEW_DISASSEMBLY__HOPPER_LICENSE_PATH` |
| `capstone_detail_mode` | bool | `True` | `DEEPVIEW_DISASSEMBLY__CAPSTONE_DETAIL_MODE` |

```toml
[disassembly]
default_engine = "ghidra"
ghidra_install_dir = "/opt/ghidra"
ghidra_jvm_args = ["-Xmx8g", "-XX:+UseG1GC"]
```

## `ClassificationConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `enabled` | bool | `True` | `DEEPVIEW_CLASSIFICATION__ENABLED` |
| `ruleset_paths` | list[str] | `[]` | `DEEPVIEW_CLASSIFICATION__RULESET_PATHS` |
| `load_builtin` | bool | `True` | `DEEPVIEW_CLASSIFICATION__LOAD_BUILTIN` |
| `anomaly_window_s` | float | `30.0` | `DEEPVIEW_CLASSIFICATION__ANOMALY_WINDOW_S` |
| `auto_inspect_on_severity` | str | `"critical"` | `DEEPVIEW_CLASSIFICATION__AUTO_INSPECT_ON_SEVERITY` |

## `ReplayConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `store_path` | Path | `user_cache_dir/sessions` | `DEEPVIEW_REPLAY__STORE_PATH` |
| `circular_buffer_seconds` | float | `60.0` | `DEEPVIEW_REPLAY__CIRCULAR_BUFFER_SECONDS` |
| `snapshot_interval_s` | float | `5.0` | `DEEPVIEW_REPLAY__SNAPSHOT_INTERVAL_S` |

## `MonitorConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_ruleset` | str | `""` | `DEEPVIEW_MONITOR__DEFAULT_RULESET` |
| `refresh_hz` | float | `4.0` | `DEEPVIEW_MONITOR__REFRESH_HZ` |
| `max_rows` | int | `25` | `DEEPVIEW_MONITOR__MAX_ROWS` |

## `DashboardConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_layout` | str | `"network"` | `DEEPVIEW_DASHBOARD__DEFAULT_LAYOUT` |
| `refresh_hz` | float | `4.0` | `DEEPVIEW_DASHBOARD__REFRESH_HZ` |
| `config_path` | str | `""` | `DEEPVIEW_DASHBOARD__CONFIG_PATH` |

## `NetworkMangleConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `queue_num` | int | `42` | `DEEPVIEW_NETWORK_MANGLE__QUEUE_NUM` |
| `state_dir` | Path | `user_cache_dir/mangle` | `DEEPVIEW_NETWORK_MANGLE__STATE_DIR` |
| `dry_run_default` | bool | `False` | `DEEPVIEW_NETWORK_MANGLE__DRY_RUN_DEFAULT` |
| `fail_open` | bool | `True` | `DEEPVIEW_NETWORK_MANGLE__FAIL_OPEN` |
| `iptables_chain` | str | `"OUTPUT"` | `DEEPVIEW_NETWORK_MANGLE__IPTABLES_CHAIN` |
| `iptables_table` | str | `"mangle"` | `DEEPVIEW_NETWORK_MANGLE__IPTABLES_TABLE` |
| `iptables_binary` | str | `"iptables"` | `DEEPVIEW_NETWORK_MANGLE__IPTABLES_BINARY` |

```toml
[network_mangle]
queue_num = 100
iptables_chain = "FORWARD"
iptables_table = "mangle"
fail_open = true
```

## `StorageConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_page_size` | int | `4096` | `DEEPVIEW_STORAGE__DEFAULT_PAGE_SIZE` |
| `default_spare_size` | int | `64` | `DEEPVIEW_STORAGE__DEFAULT_SPARE_SIZE` |
| `default_ecc` | str | `"bch8"` | `DEEPVIEW_STORAGE__DEFAULT_ECC` |
| `default_ftl` | str | `"badblock"` | `DEEPVIEW_STORAGE__DEFAULT_FTL` |
| `default_spare_layout` | str | `"onfi"` | `DEEPVIEW_STORAGE__DEFAULT_SPARE_LAYOUT` |
| `prefer_native_filesystems` | bool | `True` | `DEEPVIEW_STORAGE__PREFER_NATIVE_FILESYSTEMS` |

`default_ecc` accepts `bch8|hamming|rs|none`; `default_ftl` accepts
`badblock|mtd|ubi|jffs2|emmc_hints|ufs|none`.

```toml
[storage]
default_page_size = 2048
default_spare_size = 64
default_ecc = "bch8"
default_ftl = "ubi"
default_spare_layout = "onfi"
prefer_native_filesystems = true
```

```bash
DEEPVIEW_STORAGE__DEFAULT_ECC=rs deepview storage wrap --layer nand0 --out n
```

## `ContainersConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `allow_write` | bool | `False` | `DEEPVIEW_CONTAINERS__ALLOW_WRITE` |
| `cache_sectors` | int | `256` | `DEEPVIEW_CONTAINERS__CACHE_SECTORS` |
| `passphrase_attempts` | int | `100` | `DEEPVIEW_CONTAINERS__PASSPHRASE_ATTEMPTS` |
| `try_hidden` | bool | `False` | `DEEPVIEW_CONTAINERS__TRY_HIDDEN` |
| `pbkdf2_default_iterations` | int | `1000` | `DEEPVIEW_CONTAINERS__PBKDF2_DEFAULT_ITERATIONS` |
| `argon2_default_memory_kib` | int | `65536` | `DEEPVIEW_CONTAINERS__ARGON2_DEFAULT_MEMORY_KIB` |
| `argon2_default_iterations` | int | `3` | `DEEPVIEW_CONTAINERS__ARGON2_DEFAULT_ITERATIONS` |
| `argon2_default_parallelism` | int | `4` | `DEEPVIEW_CONTAINERS__ARGON2_DEFAULT_PARALLELISM` |

`allow_write` is a no-op in the current slice — decrypted layers are
read-only regardless. The field exists so a future write-enabled slice has a
single config flag to gate on.

```toml
[containers]
allow_write = false
cache_sectors = 512
passphrase_attempts = 200
try_hidden = true
argon2_default_memory_kib = 262144
```

## `OffloadConfig`

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `default_backend` | str | `"process"` | `DEEPVIEW_OFFLOAD__DEFAULT_BACKEND` |
| `process_workers` | int \| None | `None` (→ `os.cpu_count()`) | `DEEPVIEW_OFFLOAD__PROCESS_WORKERS` |
| `thread_workers` | int \| None | `None` | `DEEPVIEW_OFFLOAD__THREAD_WORKERS` |
| `gpu_enabled` | bool | `False` | `DEEPVIEW_OFFLOAD__GPU_ENABLED` |

`default_backend` accepts `process | thread | gpu-opencl | gpu-cuda |
remote`. `gpu_enabled=False` blocks GPU backends even when installed — an
explicit opt-in is required.

```toml
[offload]
default_backend = "gpu-cuda"
gpu_enabled = true
process_workers = 8
```

## `RemoteEndpointConfig`

Declarative remote hosts, enumerated by the `remote_image_status` plugin.
Each entry is a table under `[[remote_endpoints]]`:

| Field | Type | Default | Env var |
|-------|------|---------|---------|
| `host` | str | **required** | `DEEPVIEW_REMOTE_ENDPOINTS__<N>__HOST` |
| `transport` | str | **required** | — (one of `ssh|tcp|udp|grpc|ipmi|amt|dma`) |
| `port` | int \| None | `None` | — |
| `username` | str \| None | `None` | — |
| `identity_file` | Path \| None | `None` | — |
| `password_env` | str \| None | `None` | — |
| `known_hosts` | Path \| None | `None` | — |
| `tls_ca` | Path \| None | `None` | — |
| `require_tls` | bool | `True` | — |
| `extra` | dict[str,str] | `{}` | — |

```toml
[[remote_endpoints]]
host = "kiosk-1.lab.internal"
transport = "ssh"
username = "forensics"
identity_file = "/root/.ssh/forensics"
known_hosts = "/root/.ssh/known_hosts"
password_env = "KIOSK_PASS"

[[remote_endpoints]]
host = "bmc-1.lab.internal"
transport = "ipmi"
port = 623
username = "admin"
password_env = "BMC_PASS"
require_tls = false
```

Credentials are **never** stored inline — only environment-variable names
or filesystem paths. Dumping the parsed config never reveals a password.

## Example `config.toml`

```toml
log_level = "info"
output_format = "table"
plugin_paths = ["/opt/custom-plugins"]

[memory]
default_engine = "volatility"

[storage]
default_page_size = 2048
default_ecc = "bch8"
default_ftl = "ubi"

[offload]
default_backend = "process"
process_workers = 8

[containers]
passphrase_attempts = 500
try_hidden = true

[network_mangle]
queue_num = 200
fail_open = true

[[remote_endpoints]]
host = "target.internal"
transport = "ssh"
username = "root"
known_hosts = "/root/.ssh/known_hosts"
password_env = "TARGET_PASS"
```

## Example env overrides

```bash
export DEEPVIEW_LOG_LEVEL=debug
export DEEPVIEW_OUTPUT_FORMAT=json
export DEEPVIEW_STORAGE__DEFAULT_ECC=rs
export DEEPVIEW_OFFLOAD__GPU_ENABLED=true
export DEEPVIEW_NETWORK_MANGLE__QUEUE_NUM=100
deepview doctor
```

## Cross-references

- CLI flag overrides: [cli.md](cli.md#root-command).
- Extras that activate optional config paths: [extras.md](extras.md).
- Event types published when config-driven subsystems run: [events.md](events.md).
