# CLI Reference

Complete, option-level reference for every `deepview` subcommand. Every flag
and default on this page is read directly from the `@click.option` decorators
in `src/deepview/cli/app.py` and `src/deepview/cli/commands/*.py` — if the
source changes, update this page.

Wherever a command is only partially wired up, the description calls that out
explicitly. Commands that wrap dual-use capabilities (memory acquisition over
the network, live packet mangling, DMA attack transports, encrypted-container
unlock) document their safety gates in full.

## Root command

```text
deepview [GLOBAL OPTIONS] COMMAND [ARGS]...
```

Top-level options, all defined on `main` in `src/deepview/cli/app.py`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config PATH` | path | `None` | Configuration file path. If omitted, falls back to `~/.config/deepview/config.toml`. See [Config reference](config.md). |
| `--output-format FMT` | choice | `table` | One of `json`, `table`, `csv`, `timeline`. Overrides `output_format` on the loaded config. |
| `--log-level LEVEL` | choice | `info` | One of `debug`, `info`, `warning`, `error`. Passed to `deepview.core.logging.setup_logging`. |
| `--plugin-path PATH` | path (repeatable) | `[]` | Prepend additional plugin search paths; each `--plugin-path` occurrence is pushed to the front of `config.plugin_paths`. |
| `--no-color` | flag | `False` | Disable Rich colored output. |
| `--version` | flag | – | Print package version and exit (provided by `click.version_option`). |

=== "POSIX"

    ```bash
    deepview --log-level debug --output-format json memory analyze -i /tmp/dump.raw -p pslist
    ```

=== "PowerShell"

    ```powershell
    deepview --log-level debug --output-format json memory analyze -i .\dump.raw -p pslist
    ```

## `deepview doctor`

No options. Prints platform, architecture, detected kernel version, the capability set
returned by `PlatformInfo.detect()`, plus a live probe of every optional external tool
and Python library. See `app.py::doctor` for the exact probe list; a shortened view:

- **External tools:** `volatility3`, `frida`, `yara`, `lief`, `dtrace`, `vboxmanage`,
  `vmrun`, `virsh`.
- **Storage backends:** `pytsk3`, `pyfsapfs`, `pyfsntfs`, `pyfsxfs`, `pyfsbtrfs`,
  `pyfsf2fs`, `pyfshfs`, `pyfsext`, `zstandard`, `lz4`, `lzo`, `reedsolo`, `galois`,
  `cryptography`, `argon2`, `paramiko`, `grpc`.

Missing modules are reported as red ✗; they do not fail the command.

## `deepview plugins`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--category NAME` | string | `None` | Filter by [`PluginCategory`](events.md) value (e.g. `memory_analysis`, `credentials`). Unknown values print an error and return. |

Prints a Rich table of `name | version | category | description` derived from
each plugin's `PluginMetadata`.

## `deepview memory`

Memory forensics group. Implementations live in `cli/commands/memory.py`.

### `memory acquire`

Live memory acquisition harness — today it prints the plan and defers to
platform providers. See the `memory/acquisition/*` modules for the real work.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--method` | `lime\|avml\|winpmem\|osxpmem\|auto` | `auto` | Acquisition provider. |
| `--format` | `raw\|lime\|padded` | `raw` | Output format. |
| `--output / -o PATH` | path | **required** | Output file path. |
| `--compress` | flag | `False` | Compress output. |

### `memory analyze`

Open a memory image, register it as a layer, instantiate a plugin and run it.
Errors are caught and surface a red message + `SystemExit(1)`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--image / -i PATH` | path (must exist) | **required** | Memory image path. |
| `--plugin / -p NAME` | string | **required** | Plugin name registered with the context. |
| `--engine` | `volatility\|memprocfs\|auto` | `auto` | Analysis engine. |
| `--pid N` | int | `None` | Filter by PID (injected into plugin config). |

### `memory symbols`

Symbol-table management (stubbed; prints a yellow notice).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--generate` | flag | `False` | Generate from DWARF/kernel. |
| `--download` | flag | `False` | Download from symbol server. |
| `--list` | flag | `False` | List cached symbol tables. |

### `memory scan`

YARA scan on a memory image. Requires the `memory` extra.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--image / -i PATH` | path (must exist) | **required** | Memory image path. |
| `--rules / -r PATH` | path (must exist) | **required** | YARA rules file or directory. |
| `--rule-tag TAG` | string | `None` | Filter rules by tag. |

## `deepview vm`

VM introspection group. Today's subcommands print "VM introspection requires
a hypervisor" guidance; the real connectors live in `vm/connectors/*` and are
documented in [interfaces.md](interfaces.md#vmconnector).

### `vm list`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--hypervisor` | `qemu\|vmware\|vbox\|auto` | `auto` | Target hypervisor. |
| `--uri TEXT` | string | `""` | libvirt / VBox / VMware connection URI. |

### `vm snapshot`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--vm-id ID` | string | **required** | Target VM identifier. |
| `--name NAME` | string | **required** | Snapshot name. |

### `vm extract`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--vm-id ID` | string | **required** | Target VM identifier. |
| `--output / -o PATH` | path | **required** | Output path for the memory dump. |

### `vm analyze`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--vm-id ID` | string | **required** | Target VM identifier. |
| `--plugin / -p NAME` | string | **required** | Plugin to run after snapshot. |

## `deepview trace`

Live system tracing. Every subcommand builds a
[`TraceManager.from_context(ctx)`](interfaces.md#tracer), subscribes to the
`TraceEventBus`, and streams through `LiveRenderer` until `--duration` elapses
or SIGINT arrives. The filter DSL (`--filter`) is parsed by
`deepview.tracing.filters.parse_filter`.

Shared option stack (defined once, applied to each subcommand):

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--duration N` | int | `30` | Seconds to run. `0` = run until interrupted. |
| `--pid N` | int | `None` | Filter by PID. |
| `--uid N` | int | `None` | Filter by UID. |
| `--comm NAME` | string (repeatable) | `()` | Filter by process comm (OR semantics inside the list). |
| `--filter EXPR` | string | `None` | DSL expression merged AND-wise with the CLI-option-derived filter. |

### `trace syscall`

Trace every syscall via the `raw_syscalls:sys_enter` tracepoint. Adds
`--syscall NAME` (repeatable) which filters the stream to the named syscalls
and injects the resolved `syscall_nr` list into `KernelHints`.

### `trace network`

Same as `trace syscall` but the syscall allow-list is
`deepview.tracing.linux.syscalls.NETWORK_SYSCALLS`.

### `trace filesystem`

`FILESYSTEM_SYSCALLS` allow-list (open, read, write, unlink, rename, ...).

### `trace process`

`PROCESS_SYSCALLS` allow-list (fork, clone, execve, exit, kill, ptrace, ...).

### `trace custom`

Run a custom BCC BPF program.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--program PATH` | path (must exist) | **required** | BCC BPF C source file declaring `BPF_PERF_OUTPUT(events)` with the default `event_t` layout. |

Also inherits the shared option stack (except `--filter`). The user source is
injected into the eBPF backend via `EBPFBackend.set_override_source` before
`manager.start()`.

## `deepview instrument`

Application instrumentation group. Every subcommand prints the Frida guidance
banner unless the instrumentation extra is installed. Implementations live
under `instrumentation/` (see the `Instrumentor` abstraction in
[interfaces.md](interfaces.md#instrumentor)).

### `instrument attach`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pid N` | int | **required** | Target PID. |
| `--hooks PATH` | path (must exist) | `None` | JSON hook definitions. |

### `instrument spawn`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--program PATH` | path (must exist) | **required** | Program to launch. |
| `--hooks PATH` | path (must exist) | `None` | Hook definitions. |
| `ARGS...` | positional | `()` | Forwarded to the spawned process. |

### `instrument patch`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary PATH` | path (must exist) | **required** | Binary to patch. |
| `--output / -o PATH` | path | **required** | Output binary. |
| `--hooks PATH` | path (must exist) | `None` | Hook definitions. |
| `--strategy` | `security\|exports\|all` | `security` | Instrumentation-point selection strategy. |

### `instrument analyze`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary PATH` | path (must exist) | **required** | Binary to analyze. |

## `deepview scan`

Pattern-matching group (YARA + IoC engine). Stubbed subcommands today.

### `scan yara`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target / -t PATH` | path (must exist) | **required** | File or directory. |
| `--rules / -r PATH` | path (must exist) | **required** | YARA rules file / directory. |

### `scan ioc`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target / -t PATH` | path (must exist) | **required** | Target to scan. |
| `--ioc-file PATH` | path (must exist) | **required** | IoC indicator file. |

### `scan rules`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--list` | flag | `False` | List configured rule sets. |
| `--update` | flag | `False` | Update rule sets (not yet implemented). |

## `deepview report`

Forensic report generation. `generate` is wired into `ReportEngine`; the
other subcommands are partial.

### `report generate`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--session ID` | string | `None` | Session ID (reserved; not yet used). |
| `--template` | `html\|markdown` | `html` | Template kind. |
| `--output / -o PATH` | path | `None` | Output file; if omitted, rendered text is printed to stdout. |

### `report timeline`

Prints a placeholder message today.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--session ID` | string | `None` | Reserved. |
| `--output / -o PATH` | path | `None` | Output file. |

### `report export`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--session ID` | string | `None` | Reserved. |
| `--format` | `stix\|attck\|json` | `stix` | Output format. |
| `--output / -o PATH` | path | `None` | Output file. |

## `deepview disassemble`

Address parsing accepts decimal and `0x`/`0X` hex; bounds are
`[0, 2^64-1]`. Helper `_parse_address` is in `cli/commands/disassemble.py`.

### `disassemble disasm`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary / -b PATH` | path (must exist) | **required** | Binary. |
| `--address / -a TEXT` | string | `None` | Start address (hex or decimal). Mutually exclusive with `--function`. |
| `--function / -f NAME` | string | `None` | Function name. |
| `--count / -n N` | int | `20` | Number of instructions to print. |
| `--engine` | `ghidra\|hopper\|capstone\|auto` | `auto` | Backend. |

### `disassemble decompile`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary / -b PATH` | path (must exist) | **required** | Binary. |
| `--function / -f NAME_OR_ADDR` | string | **required** | Function name or hex address. |
| `--engine` | `ghidra\|hopper\|auto` | `auto` | Backend. |

### `disassemble functions`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary / -b PATH` | path (must exist) | **required** | Binary. |
| `--engine` | `ghidra\|hopper\|capstone\|auto` | `auto` | Backend. |
| `--filter GLOB` | string | `None` | `fnmatch` pattern applied to each function name. |

### `disassemble xrefs`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary / -b PATH` | path (must exist) | **required** | Binary. |
| `--address / -a TEXT` | string | **required** | Target address. |
| `--direction` | `to\|from\|both` | `to` | Xref direction. |
| `--engine` | `ghidra\|hopper\|auto` | `auto` | Backend. |

### `disassemble cfg`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary / -b PATH` | path (must exist) | **required** | Binary. |
| `--function / -f NAME_OR_ADDR` | string | **required** | Function. |
| `--engine` | `ghidra\|hopper\|auto` | `auto` | Backend. |
| `--format` | `json\|dot\|table` | `table` | Output format. `dot` is suitable for Graphviz. |

### `disassemble strings`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--binary / -b PATH` | path (must exist) | **required** | Binary. |
| `--min-length N` | int | `4` | Minimum string length. |
| `--engine` | `ghidra\|hopper\|capstone\|auto` | `auto` | Backend. |

## `deepview replay`

Record live trace sessions into a SQLite database and replay them later.

### `replay record`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output PATH` | path | **required** | Session database file. |
| `--duration N` | int | `30` | Record duration in seconds. |
| `--pid N` | int | `None` | Filter by PID. |
| `--filter EXPR` | string | `None` | DSL filter. |
| `--snapshot-every S` | float | `0.0` | Seconds between `/proc` snapshots (`0` = none). |
| `--circular-seconds S` | float | `60.0` | Size of the pre-event ring buffer in seconds. |

### `replay list`

Positional `SESSION_DB` (path, must exist). Prints a table of stored sessions.

### `replay show`

Positional `SESSION_DB`. Options:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--session ID` | string | `None` | Session to show. If omitted, shows the most recent. |
| `--pid N` | int | `None` | Filter rows by PID. |
| `--category NAME` | string | `None` | Filter by event category. |
| `--limit N` | int | `100` | Cap row count. |

### `replay play`

Positional `SESSION_DB`. Options:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--session ID` | string | `None` | Session to replay (latest if omitted). |
| `--speed FLOAT` | float | `0.0` | `0` = instant, `1` = realtime, `N` = Nx. |
| `--ruleset PATH` | path (must exist) | `None` | YAML classification ruleset applied during replay. |

## `deepview inspect`

On-demand inspection of the live Linux host.

### `inspect process`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pid N` | int | **required** | Target PID. |

### `inspect file`

Positional `PATH` (not required to exist). Prints hash + magic + mount attribution.

### `inspect memory`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pid N` | int | **required** | Target PID. |
| `--yara PATH` | path (must exist) | `None` | YARA rules; when set, runs a YARA scan over the live process. |
| `--va HEX` | string | `None` | Virtual address to read (hex). |
| `--length N` | int | `256` | Bytes to read at `--va`. |

Default output is the process memory region map.

### `inspect net`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pid N` | int | `None` | Filter by owning PID. |

## `deepview monitor`

Long-running forensic monitor. Layers classification + pre-event context
capture + auto-inspection on top of the trace stream.

### `monitor tail`

Live tail with no persistence.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--duration N` | int | `30` | Seconds to run. |
| `--pid N` | int | `None` | Filter by PID. |
| `--filter EXPR` | string | `None` | DSL filter. |

### `monitor alert`

Classify the trace stream, write matches + snapshots to a session DB.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ruleset PATH` | path (must exist) | `None` | YAML ruleset; falls back to the built-in Linux baseline. |
| `--output PATH` | path | `None` | Persist matching events + snapshots to a session DB. |
| `--duration N` | int | `60` | Seconds to run. |
| `--pid N` | int | `None` | Filter by PID. |
| `--filter EXPR` | string | `None` | DSL filter. |
| `--auto-inspect / --no-auto-inspect` | bool | `True` | Auto-capture a [`ProcessInspector`](interfaces.md) snapshot on every `critical` classification. |

## `deepview dashboard`

Multi-panel Rich dashboard built on `rich.layout.Layout`. Layouts are YAML
files; named built-ins live under `src/deepview/cli/dashboard/builtin_layouts/`.

### `dashboard layouts`

No options. Prints a table of built-in layouts + their panel list.

### `dashboard show PATH`

Positional `CONFIG_PATH` (must exist). Parses a custom layout and prints its
panel list, `refresh_hz`, and `trace.*` config.

### `dashboard run`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layout NAME` | string | `None` | Built-in layout name. Mutually exclusive with `--config`. |
| `--config PATH` | path (must exist) | `None` | Custom layout YAML. |
| `--duration N` | int | `0` | `0` = run until interrupted. |
| `--filter EXPR` | string | `None` | Additional trace filter (ANDed with the layout's). |
| `--pid N` | int | `None` | Filter trace stream by PID. |
| `--ruleset PATH` | path (must exist) | `None` | Classification ruleset (overrides the one in the layout). |
| `--enable-mangle` | flag | `False` | Also run the mangle engine. Requires `--mangle-rules`. |
| `--mangle-rules PATH` | path (must exist) | `None` | Mangle ruleset YAML. |
| `--mangle-queue N` | int | `None` | NFQUEUE number (overrides ruleset). |
| `--mangle-dry-run` | flag | `False` | Force every verdict to ACCEPT. |
| `--install-iptables` | flag | `False` | Install + remove the NFQUEUE jump rule; otherwise expect operator to pre-install it. |
| `--confirm` | flag | `False` | Skip the interactive mangle confirmation prompt. |

When `--enable-mangle` is set, every safety gate from `netmangle run` applies
(root, non-empty ruleset, confirmation, fail-open on exception). See
[netmangle](#deepview-netmangle).

## `deepview netmangle`

Live packet mangling through NFQUEUE. **Dual-use** — scope to authorized
security testing, CTF, honeypot, and defensive research only. Every path
into `run` is safety-gated; see below.

### `netmangle validate RULES`

Positional `RULES` (must exist). Parses the YAML, prints rule list + SHA-256
head + `default_verdict` + `fail_open`.

### `netmangle status`

No options. Prints any leftover iptables NFQUEUE rules recorded in the state
file (`~/.cache/deepview/mangle_state.json` by default).

### `netmangle run`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rules PATH` | path (must exist) | **required** | Mangle ruleset YAML. |
| `--queue N` | int | `None` | Override ruleset `queue:` key. |
| `--enable-mangle` | flag | `False` | Required opt-in. Refuses to start without it. |
| `--confirm` | flag | `False` | Skip the interactive prompt (unavoidable otherwise). |
| `--dry-run` | flag | `False` | Force every verdict to ACCEPT. |
| `--install-iptables` | flag | `False` | Install + remove the NFQUEUE jump rule. |
| `--direction` | `in\|out` | `out` | Traffic direction. |
| `--duration N` | int | `0` | `0` = run until interrupted. |
| `--output PATH` | path | `None` | Persist a session DB with alert events + final stats. |

**Refused when any of the following fails:** missing `--enable-mangle`,
non-root, empty ruleset, `queue_num <= 0`, operator declines the confirmation
prompt.

## `deepview offload`

Offload engine — dispatches KDF / crypto work to thread / process / GPU /
remote backends. See [interfaces.md](interfaces.md#offloadbackend).

### `offload status`

No options. Prints a table of every registered backend + availability +
capabilities + in-flight count from `context.offload.status()`.

### `offload run`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--kind` | `pbkdf2_sha256\|argon2id\|sha512` | **required** | Job kind; maps to `deepview.offload.kdf:*`. |
| `--json-input PATH` | path (must exist) | **required** | JSON payload file. String fields ending in `_hex` are decoded as hex under the stripped key. |
| `--backend NAME` | string | `None` | Override default backend. |

### `offload benchmark`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--kind` | `pbkdf2_sha256\|argon2id\|sha512` | **required** | Job kind. |
| `--iterations N` | int | `8` | Number of synthetic jobs. |
| `--backend NAME` | string | `None` | Override default backend. |

## `deepview remote-image`

**Dual-use** remote memory acquisition. Every subcommand shares the same
option stack (`_common_options`) plus a hard authorization/banner/delay
pattern in `cli/commands/remote_image.py::_authorize_and_banner`.

**Shared gates:**

- `--confirm` is required.
- `--authorization-statement` must resolve to a non-empty string. Accepts
  `env:NAME`, `file:/path`, bare path, or a literal non-empty inline statement.
- A 5-second banner precedes any network traffic. `^C` during the delay aborts.
- `--dry-run` short-circuits before network traffic, printing the plan.
- DMA transports add `--enable-dma` + root check.

Shared options:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--host TEXT` | string | **required** | Target host or IP. |
| `--port N` | int | `None` | Transport port. |
| `--username TEXT` | string | `None` | Remote user. |
| `--identity-file PATH` | path | `None` | SSH private key. |
| `--known-hosts PATH` | path | `None` | SSH known_hosts. Required for `ssh` unless `--no-require-tls`. |
| `--tls-ca PATH` | path | `None` | TLS CA bundle. Required for `agent` unless `--no-require-tls`. |
| `--password-env NAME` | string | `None` | Env var holding the password (never inline). |
| `--output / -o PATH` | path | **required** | Local output path. |
| `--format` | [DumpFormat](config.md) | `raw` | Output format. |
| `--source TEXT` | string | `None` | Remote source path (e.g. `/dev/mem`, `/proc/kcore`). |
| `--confirm` | flag | `False` | Dual-use opt-in. |
| `--authorization-statement TEXT` | string | `None` | `env:NAME`, `file:/path`, or inline. |
| `--dry-run` | flag | `False` | Plan-only. |
| `--require-tls / --no-require-tls` | bool | `True` | Abort if TLS material missing. |

### Subcommands

| Name | Transport | Extra flags | Description |
|------|-----------|-------------|-------------|
| `ssh` | `ssh-dd` | – | `ssh host 'sudo dd if=/dev/mem bs=1M'`. `--known-hosts` required when TLS verification on. |
| `tcp` | `tcp-stream` | – | Bind a TCP listener and accept one external streamer. |
| `agent` | `network-agent` | – | Pull memory from a pre-deployed `deepview-agent`. `--tls-ca` required when TLS verification on. |
| `lime` | `lime-remote` | – | Remote LiME acquisition (slice 20). |
| `ipmi` | `ipmi` | – | IPMI out-of-band acquisition. |
| `amt` | `intel-amt` | – | Intel AMT out-of-band acquisition. |
| `dma-tb` | `dma-thunderbolt` | `--enable-dma` (flag, required) | Thunderbolt DMA. Root. |
| `dma-pcie` | `dma-pcie` | `--enable-dma` | PCIe DMA. Root. |
| `dma-fw` | `dma-firewire` | `--enable-dma` | Firewire DMA. Root. |

## `deepview storage`

Storage subsystem — NAND wrapping, filesystem mounting, adapter probes.
None of these commands require root.

### `storage info`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Registered layer name. |

Prints every adapter that recognised the layer.

### `storage wrap`

Compose `RawNAND -> (optional ECC) -> (optional FTL)` and register the result.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Raw NAND layer to wrap. |
| `--out NAME` | string | **required** | Name to register the wrapped layer as. |
| `--ecc` | `bch8\|hamming\|rs` | `None` | ECC backend. |
| `--spare-layout` | `onfi\|samsung_klm\|toshiba_tc58\|micron_mt29f` | `onfi` | NAND spare layout preset. |
| `--ftl` | `ubi\|jffs2\|mtd\|badblock` | `None` | FTL translator. |
| `--page-size N` | int | `2048` | NAND page size. |
| `--spare-size N` | int | `64` | OOB size. |
| `--pages-per-block N` | int | `64` | Pages per block. |
| `--blocks N` | int | `2048` | Block count. |

### `storage mount`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Source layer. |
| `--fs NAME` | string | `None` | Filesystem adapter name (auto-probe if omitted). |

Registers the opened filesystem under `<layer>-fs`.

### `storage list`

No options. Dumps four tables: registered layers, filesystem adapters, FTL
translators, ECC decoders.

## `deepview filesystem`

Filesystem inspection over a registered `DataLayer`. Every subcommand accepts
`--fs-type` (defaults to `auto`) and `--offset` (defaults to `0`).

### `filesystem ls`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Layer name. |
| `--fs-type NAME` | string | `auto` | Adapter override. |
| `--offset N` | int | `0` | Byte offset. |
| `--path TEXT` | string | `/` | Directory path. |
| `--recursive` | flag | `False` | Recursive walk. |
| `--include-deleted` | flag | `False` | Surface deleted entries. |

### `filesystem cat`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Layer name. |
| `--path TEXT` | string | **required** | File path. |
| `--fs-type NAME` | string | `auto` | Adapter override. |
| `--offset N` | int | `0` | Byte offset. |

Writes file bytes to stdout.

### `filesystem stat`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Layer name. |
| `--path TEXT` | string | **required** | Entry path. |
| `--fs-type NAME` | string | `auto` | Adapter override. |
| `--offset N` | int | `0` | Byte offset. |

Renders `FSEntry` fields as a key/value table.

### `filesystem find`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--layer NAME` | string | **required** | Layer name. |
| `--pattern TEXT` | string | **required** | fnmatch or regex pattern. |
| `--regex` | flag | `False` | Treat `--pattern` as a Python regex. |
| `--fs-type NAME` | string | `auto` | Adapter override. |
| `--offset N` | int | `0` | Byte offset. |

## `deepview unlock`

Encrypted-volume unlock group. Every command today produces a **read-only**
decrypted layer even when `--enable-write` is passed.

### `unlock luks IMAGE`

Positional `IMAGE` (must exist). Options:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--passphrase-env NAME` | string | `None` | Env var holding the passphrase. |
| `--keyfile PATH` | path (must exist) | `None` | Keyfile (SHA-256 hashed to derive the key). |
| `--master-key-hex HEX` | string | `None` | 32- or 64-byte hex master key. |
| `--mount NAME` | string | `None` | Register the decrypted layer under this name. |
| `--register-as NAME` | string | `None` | Alias for `--mount`. |
| `--confirm` | flag | `False` | Required with `--enable-write`. |
| `--enable-write` | flag | `False` | No-op in this slice; decrypted layers are read-only. |
| `--offset N` | int | `0` | Byte offset of the LUKS header inside `IMAGE`. |

If none of `--master-key-hex / --keyfile / --passphrase-env` are set, `unlock luks`
prompts interactively via `getpass`.

### `unlock veracrypt IMAGE`

Positional `IMAGE`. Options:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--passphrase-env NAME` | string | `None` | Env var holding the passphrase. |
| `--master-key-hex HEX` | string | `None` | 64-byte header key. |
| `--try-hidden` | flag | `False` | Probe for a trailing hidden-volume header. |
| `--pim N` | int | `0` | Personal Iterations Multiplier. |
| `--system / --volume` | bool | `False` | System-encryption iteration table. |
| `--mount NAME` | string | `None` | Registration name. |
| `--register-as NAME` | string | `None` | Alias for `--mount`. |

### `unlock truecrypt IMAGE`

Same as `veracrypt` minus `--pim`.

### `unlock auto IMAGE`

Positional `IMAGE`. Tries every registered unlocker + (optionally) scans a
memory dump for AES / LUKS / BitLocker / FileVault master keys.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--memory-dump PATH` | path (must exist) | `None` | Memory image to scan for master-key candidates. |
| `--passphrase-list PATH` | path (must exist) | `None` | Newline-delimited dictionary. |
| `--keyfile PATH` | path (must exist) | `None` | Single keyfile. |
| `--try-hidden` | flag | `False` | Also probe for hidden VeraCrypt/TrueCrypt volumes. |
| `--register-as-prefix TEXT` | string | `None` | Registration name prefix. |
| `--confirm` | flag | `False` | Confirm scanning a memory dump. If unset, prompts interactively. |

When `--memory-dump` is set, a dual-use banner prints and
`click.confirm` gates the scan unless `--confirm` is already on.

## `deepview unlock-native`

Temporary fork for BitLocker / FileVault 2 (will be folded into
`deepview unlock` after slice 15 merges). Every subcommand takes `IMAGE` as
a positional (must exist) and requires `--confirm`. Secrets only flow through
environment variables — never argv.

### `unlock-native bitlocker IMAGE`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--recovery-password ENV_VAR` | string | `None` | Env var holding the 48-digit recovery password. |
| `--passphrase-env NAME` | string | `None` | Env var holding the user password. |
| `--keyfile PATH` | path (must exist) | `None` | BitLocker startup key (`.BEK`). |
| `--fvek-hex HEX` | string | `None` | Full Volume Encryption Key as hex. |
| `--fvek-from-memory LAYER` | string | `None` | Registered memory layer to scan for an FVEK candidate. |
| `--register-as NAME` | string | `None` | Register the decrypted layer. |
| `--confirm` | flag | `False` | Required. |

### `unlock-native filevault IMAGE`

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--passphrase-env NAME` | string | `None` | Env var with the user password. |
| `--recovery-password-env NAME` | string | `None` | Env var with the recovery key. |
| `--volume-key-hex HEX` | string | `None` | Volume key extracted from memory. |
| `--register-as NAME` | string | `None` | Register the decrypted layer. |
| `--confirm` | flag | `False` | Required. |

## Cross-references

- Event types published by each subsystem: [events.md](events.md).
- Abstract interfaces each concrete provider implements: [interfaces.md](interfaces.md).
- Config sections and env-var overrides: [config.md](config.md).
- Optional dependency extras: [extras.md](extras.md).
