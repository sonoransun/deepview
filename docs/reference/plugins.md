# Plugins Reference

Every builtin plugin ships in `src/deepview/plugins/builtin/` and is
registered via the `@register_plugin` decorator. Import order in
`plugins/builtin/__init__.py` matters — a plugin file never imported from
that module silently fails to register.

Third-party plugins declared under `[project.entry-points."deepview.plugins"]`
and directory-scan plugins under `config.plugin_paths` compose into the same
registry; see `src/deepview/plugins/registry.py` for the three-tier
discovery order.

All plugins subclass [`DeepViewPlugin`](interfaces.md#deepviewplugin).
Each `run()` returns a [`PluginResult`](interfaces.md#deepviewplugin) — a
column list + row dicts + a free-form metadata dict.

## Plugin catalog

| Name | Category | Requires (kwargs) | Outputs (columns) | Module |
|------|----------|-------------------|-------------------|--------|
| `pslist` | `memory_analysis` | `image_path`, `engine` (opt, default `auto`), `pid` (opt) | `PID`, `PPID`, `Name`, `Threads`, `Handles`, `CreateTime` (Volatility) or `PID`, `PPID`, `Name` (memprocfs) | `plugins/builtin/pslist.py` |
| `netstat` | `network_analysis` | `image_path`, `os_hint` (opt) | `Proto`, `LocalAddr`, `LocalPort`, `RemoteAddr`, `RemotePort`, `State`, `PID`, `Process` | `plugins/builtin/netstat.py` |
| `malfind` | `malware_detection` | `image_path`, `engine` (opt), `pid` (opt) | `PID`, `Process`, `Address`, `VadTag`, `Protection`, `Flags`, `Hexdump` | `plugins/builtin/malfind.py` |
| `timeliner` | `timeline` | `image_path` | `Timestamp`, `Type`, `Description`, `Source` | `plugins/builtin/timeliner.py` |
| `dkom_detect` | `malware_detection` | `image_path` | `PID`, `Name`, `Source`, `Hidden`, `DetectionMethod` | `plugins/builtin/dkom_detect.py` |
| `credentials` | `credentials` | `image_path` | `Type`, `Source`, `Username`, `Value`, `Offset` | `plugins/builtin/credentials.py` |
| `pagetable_walk` | `memory_analysis` | `image_path`, `limit` (opt) | `CR3`, `Virtual`, `Physical`, `Size`, `RW`, `User`, `NX`, `Level` | `plugins/builtin/pagetable_walk.py` |
| `strings` | `memory_analysis` | `image_path`, `encodings` (opt), `min_length` (opt) | `Offset`, `Encoding`, `Length`, `String`, `Entropy` | `plugins/builtin/strings.py` |
| `command_history` | `artifact_recovery` | `image_path`, `limit` (opt) | `Shell`, `Command`, `Offset`, `PID` | `plugins/builtin/command_history.py` |
| `linux_proc` | `artifact_recovery` | `limit` (opt) | `PID`, `PPID`, `UID`, `Comm`, `State`, `Threads`, `FDs`, `RSS(KB)`, `Exe`, `Cmdline` | `plugins/builtin/linux_proc.py` |
| `linux_netstat` | `network_forensics` | – | `Proto`, `Local`, `Remote`, `State`, `UID`, `PID`, `Comm` | `plugins/builtin/linux_netstat.py` |
| `linux_ns` | `artifact_recovery` | – | `PID`, `Comm`, `pid_ns`, `net_ns`, `mnt_ns`, `user_ns`, `Diverges` | `plugins/builtin/linux_ns.py` |
| `linux_modules` | `rootkit_detection` | – | `Name`, `Size`, `Refs`, `Deps`, `State`, `Address`, `Taints` | `plugins/builtin/linux_modules.py` |
| `linux_kernel_taint` | `rootkit_detection` | – | `Key`, `Value` | `plugins/builtin/linux_kernel_taint.py` |
| `remote_image_status` | `network_forensics` | – | `Host`, `Transport`, `Port`, `Provider`, `Available`, `TLSRequired`, `CredentialsResolved` | `plugins/builtin/remote_image_status.py` |
| `filesystem_ls` | `artifact_recovery` | `layer_name`, `fs_type` (opt, `auto`), `offset` (opt, `0`), `path` (opt, `/`), `recursive` (opt), `include_deleted` (opt), `limit` (opt) | `Path`, `Size`, `Mode`, `MTime`, `Deleted` | `plugins/builtin/filesystem_ls.py` |
| `filesystem_timeline` | `artifact_recovery` | `layer_name`, `fs_type` (opt), `offset` (opt), `include_deleted` (opt, `True`) | `Time`, `Type`, `Path`, `Size` | `plugins/builtin/filesystem_timeline.py` |
| `nand_decode` | `artifact_recovery` | `layer_name`, `page_size`, `spare_size`, `pages_per_block`, `blocks`, `ecc` (opt), `ftl` (opt), `spare_layout` (opt, `onfi`) | `Metric`, `Value` | `plugins/builtin/nand_decode.py` |
| `swap_extract` | `artifact_recovery` | `layer_name`, `output_path`, `kind` (opt, `linux`), `chunk_size` (opt) | `Metric`, `Value` | `plugins/builtin/swap_extract.py` |
| `deleted_file_carve` | `artifact_recovery` | `layer_name`, `fs_type` (opt), `offset` (opt), `max_entries` (opt) | `Source`, `Offset`, `Size`, `Snippet` | `plugins/builtin/deleted_file_carve.py` |
| `volume_unlock` | `credentials` | (none required) | `Layer`, `Format`, `Cipher`, `CandidateKeys`, `DataOffset`, `DataLength` | `plugins/builtin/volume_unlock.py` |
| `extracted_keys` | `credentials` | `layer_name` (opt) | `KeyType`, `Offset`, `Confidence`, `Description`, `KeyDataPreview` | `plugins/builtin/extracted_keys.py` |

On any error, plugins degrade to a single-column `Error` result containing the
failure message — every plugin follows this convention for consistent CLI UX.

## Category index

- **Memory analysis**: `pslist`, `malfind`, `pagetable_walk`, `strings`.
- **Network**: `netstat`, `linux_netstat`, `remote_image_status`.
- **Malware / rootkit**: `dkom_detect`, `linux_modules`, `linux_kernel_taint`.
- **Artifact recovery**: `timeliner`, `command_history`, `linux_proc`, `linux_ns`,
  `filesystem_ls`, `filesystem_timeline`, `nand_decode`, `swap_extract`,
  `deleted_file_carve`.
- **Credentials**: `credentials`, `volume_unlock`, `extracted_keys`.

## New plugins in the storage / offload / containers / remote release

### `linux_proc`

Live `/proc` walker. Opens every numeric directory under `/proc`, reads
`status`, `cmdline`, `fd/`, `maps`, `ns/`, `cgroup`, and yields one row per
process with its RSS, thread count, FD count, and exe path. Stdlib-only; no
optional deps.

```bash
deepview memory analyze -i unused -p linux_proc  # layer is ignored; live source
```

Most `deepview inspect process --pid N` output is a single-row projection of
this plugin.

### `linux_kernel_taint`

One-sheet hardening snapshot: kernel taint bits (`/proc/sys/kernel/tainted`),
`modules_disabled`, `kptr_restrict`, `dmesg_restrict`, `Yama`
`ptrace_scope`. Useful for quickly spotting whether a host has ever loaded an
out-of-tree module or had its `ptrace_scope` weakened.

```bash
deepview memory analyze -i unused -p linux_kernel_taint
```

### `filesystem_ls`

The plugin-face equivalent of `deepview filesystem ls`. Takes a registered
`DataLayer` name, opens the filesystem through `context.storage`, and emits
`Path / Size / Mode / MTime / Deleted` rows. Honors `recursive`,
`include_deleted`, and an optional row `limit`.

```bash
deepview memory analyze -i unused -p filesystem_ls \
    --plugin-config layer_name=disk0 --plugin-config path=/var/log
```

### `filesystem_timeline`

Walks every entry in a filesystem and emits a bodyfile-style MAC-times
timeline (one row per time-type per entry). Output is suitable for
consumption by `mactime`-style tools.

```bash
deepview memory analyze -i unused -p filesystem_timeline \
    --plugin-config layer_name=disk0
```

### `nand_decode`

Walks a registered raw-NAND layer, applies an ECC decoder, and feeds the
result through an FTL translator. Outputs corrected/uncorrectable page
counts and FTL-specific stats (UBI PEB count, bad-block count, etc.).

```bash
deepview storage wrap --layer nand0 --out nand_ftl --ecc bch8 --ftl ubi
deepview memory analyze -i unused -p nand_decode \
    --plugin-config layer_name=nand_ftl
```

### `swap_extract`

Dumps Linux swap / zram / zswap / Windows pagefile pages to a flat
file, transparently decompressing LZO/LZ4/Zstd/Snappy chunks where applicable.

```bash
deepview memory analyze -i unused -p swap_extract \
    --plugin-config layer_name=swap0 --plugin-config output_path=/tmp/swap.bin
```

Requires the `compression` extra for non-default codecs; the plugin returns
`available=False` metadata when the backend or its optional deps are missing.

### `deleted_file_carve`

Uses the `unallocated()` iterator on each filesystem adapter to surface
deleted entries and slack-space strings. Combines well with Sleuth Kit
(`pytsk3`) under the hood when you use the TSK adapter.

```bash
deepview memory analyze -i unused -p deleted_file_carve \
    --plugin-config layer_name=disk0
```

### `volume_unlock`

Read-only inventory of every encrypted container detected across registered
layers + the master-key candidates currently in memory. Does **not** attempt
an unlock — call `deepview unlock` or `deepview unlock-native` for that.

```bash
deepview memory analyze -i unused -p volume_unlock
```

### `extracted_keys`

Runs `EncryptionKeyScanner` against a memory layer and summarises every
AES key schedule, LUKS/BitLocker/FileVault master key, and high-entropy blob
it finds. Publishes candidate keys that the container subsystem will
automatically try during `unlock auto`.

```bash
deepview memory analyze -i vmcore.bin -p extracted_keys \
    --plugin-config layer_name=vmcore
```

### `remote_image_status`

Lists every `RemoteEndpointConfig` in the current `DeepViewConfig`, its
transport, provider class, availability, whether TLS verification material
is present, and whether the credential source resolves. Critically, it never
reveals the credential itself — only whether `os.environ.get(password_env)`
is non-empty. Pairs with [`deepview remote-image`](cli.md#deepview-remote-image)
for dry-run-style inventory:

```bash
deepview memory analyze -i unused -p remote_image_status
```

## Plugin configuration

Every plugin accepts an arbitrary `config` dict. Typical wire-up patterns:

- **CLI path:** `deepview memory analyze` injects `image_path`, `engine`, and
  `pid` from the CLI flags. Additional fields require a custom command.
- **Python path:** `context.plugins.instantiate("pslist", config={...})`
  returns a configured instance, and `instance.run()` returns a `PluginResult`.
- **Session path:** `deepview monitor alert --output session.db` stores
  `auto-inspect` snapshots for every `critical` classification.

## Writing a new plugin

1. Subclass [`DeepViewPlugin`](interfaces.md#deepviewplugin).
2. Decorate with `@register_plugin(name=..., category=..., description=...,
   tags=..., platforms=...)`.
3. Implement `get_requirements()` returning a list of
   [`Requirement`](interfaces.md) instances.
4. Implement `run()` to return a `PluginResult`.
5. If builtin: add an import in `plugins/builtin/__init__.py`. If third-party:
   register under `[project.entry-points."deepview.plugins"]`. If directory:
   drop the `.py` file under `config.plugin_paths`.

Skeleton:

```python
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin
from deepview.core.types import PluginCategory

@register_plugin(
    name="my_plugin",
    category=PluginCategory.CUSTOM,
    description="Does a thing",
    tags=["demo"],
)
class MyPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls):
        return [Requirement(name="layer_name", description="Registered DataLayer name")]

    def run(self) -> PluginResult:
        layer = self.context.layers.get(self.config["layer_name"])
        return PluginResult(columns=["Offset", "Length"], rows=[{"Offset": 0, "Length": 42}])
```

## Per-plugin notes and examples

### `pslist` (memory analysis)

Delegates to the active [`AnalysisEngine`](interfaces.md#analysisengine) —
`VolatilityEngine.engine_name()` returns the full 6-column schema; MemProcFS
returns the reduced 3-column schema. On error (image not parseable, engine
unavailable), produces a single-column `Error` row.

=== "CLI"

    ```bash
    deepview memory analyze -i dump.raw -p pslist
    deepview memory analyze -i dump.raw -p pslist --pid 4321
    ```

=== "Python"

    ```python
    from deepview.core.context import AnalysisContext
    ctx = AnalysisContext.for_testing()
    plugin = ctx.plugins.instantiate("pslist", config={"image_path": "dump.raw", "engine": "auto"})
    print(plugin.run().rows[:5])
    ```

### `netstat` (network analysis)

Opens the memory image through `MemoryManager`, applies the OS hint, extracts
every socket object it can find. Reports owner PID + process name when the
engine exposes that mapping.

### `malfind` (malware detection)

Uses the Volatility 3 `malfind` plugin internally. Flags VADs that are both
`MEM_PRIVATE` and `PAGE_EXECUTE_READWRITE` (or the platform equivalent).

### `timeliner` (timeline)

Runs every engine-level temporal source (process create-times, registry keys,
browser history cached in memory, ...) through the MFT-style emitter.

### `dkom_detect` (malware detection)

Cross-references kernel objects (`EPROCESS` linked list / `task_struct`) to
surface hidden processes. Not all platform combinations are wired; a
single-row note surfaces when the engine cannot provide one of the sources.

### `credentials` (credentials)

Scans for credential artifacts using the memory analysis engine: lsass
secrets on Windows, hashed passwords in kernel structures, browser credential
caches, etc.

### `pagetable_walk` (memory analysis)

Locates candidate CR3 values by scanning for PML4 entries and walks every
viable page table.

### `strings` (memory analysis)

Pure-Python carver with entropy filtering. `encodings` defaults to
`ascii,utf-16-le`; comma-separate to add more (e.g. `ascii,utf-16-le,utf-16-be`).

### `command_history` (artifact recovery)

Identifies cmd.exe / PowerShell / bash history buffers in memory by looking
for the platform-specific ring buffers and decodes each command.

### `linux_proc`, `linux_netstat`, `linux_ns`, `linux_modules`, `linux_kernel_taint`

Every Linux live plugin is **stdlib-only** — they walk `/proc` directly
without requiring the `memory` extra. Use `--image unused` on the CLI to
keep the `memory analyze` wrapper happy.

### `filesystem_ls`, `filesystem_timeline`, `nand_decode`, `swap_extract`, `deleted_file_carve`, `volume_unlock`, `extracted_keys`, `remote_image_status`

See above (storage/offload/containers/remote release section) for detailed
prose and sample invocations.

## Writing a new plugin

1. Subclass [`DeepViewPlugin`](interfaces.md#deepviewplugin).
2. Decorate with `@register_plugin(name=..., category=..., description=...,
   tags=..., platforms=...)`.
3. Implement `get_requirements()` returning a list of
   [`Requirement`](interfaces.md) instances.
4. Implement `run()` to return a `PluginResult`.
5. If builtin: add an import in `plugins/builtin/__init__.py`. If third-party:
   register under `[project.entry-points."deepview.plugins"]`. If directory:
   drop the `.py` file under `config.plugin_paths`.

Additional skeleton with events:

```python
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin
from deepview.core.events import ArtifactRecoveredEvent
from deepview.core.types import PluginCategory

@register_plugin(
    name="my_artifact_plugin",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Extract and publish a demo artifact",
    tags=["demo", "artifact"],
)
class MyArtifactPlugin(DeepViewPlugin):
    @classmethod
    def get_requirements(cls):
        return [
            Requirement(name="layer_name", description="Registered DataLayer name"),
            Requirement(name="limit", description="Row cap", required=False, default=1000),
        ]

    def run(self) -> PluginResult:
        layer = self.context.layers.get(self.config["layer_name"])
        rows = list(self._extract(layer, limit=int(self.config.get("limit", 1000))))
        self.context.events.publish(
            ArtifactRecoveredEvent(
                artifact_type="demo",
                source=self.config["layer_name"],
                count=len(rows),
                metadata={"plugin": "my_artifact_plugin"},
            )
        )
        return PluginResult(
            columns=["Offset", "Length", "Preview"],
            rows=rows,
            metadata={"total_found": len(rows)},
        )

    def _extract(self, layer, limit):
        yield from ()
```

## Entry-point registration

For third-party distribution, declare the plugin in your own
`pyproject.toml`:

```toml
[project.entry-points."deepview.plugins"]
my_artifact_plugin = "my_package.plugins:MyArtifactPlugin"
```

Deep View discovers it on next `context.plugins` access. Directory-scan
plugins under `config.plugin_paths` are also supported but **symlinked
directories are refused** by `PluginRegistry` for safety, and files starting
with `_` are skipped.

## Cross-references

- [interfaces.md#deepviewplugin](interfaces.md#deepviewplugin) for the ABC.
- [events.md](events.md) for every event type plugins may publish via
  `self.context.events.publish(...)`.
- [cli.md](cli.md) for CLI subcommands that drive or surface plugin results.
- [extras.md](extras.md) for the optional dependencies each plugin needs.
