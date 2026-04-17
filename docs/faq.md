# FAQ

Grouped by topic. If your question isn't here, try
[troubleshooting](troubleshooting.md) (concrete problem→fix entries) or
open a discussion on the repo.

---

## Installation

### Why is Volatility 3 not in the base install?

Because most users never run Volatility plugins — they acquire, they
carve, they unlock, they trace. `volatility3` is ~80 MB of wheels
including a symbol-table download path, so we keep it optional:

```bash
pip install -e ".[memory]"
```

After that, `deepview doctor` reports "volatility: available" and
`MemoryManager.get_engine("auto")` returns a `VolatilityEngine`.

### Why are there so many extras?

Deep View spans ten loosely-coupled subsystems, each with heavy
optional dependencies. A disk-forensics user doesn't need `bcc`; an
eBPF tracing user doesn't need `libbde`. Extras let the core install
stay under 30 MB while every subsystem can still pull in its own heavy
tooling. The full matrix lives in
[`reference/extras.md`](reference/extras.md).

### I installed `[all]` and pip is unhappy. What do I try first?

`pip install -e ".[all,dev]"` compiles native extensions for
`yara-python`, `frida`, `bcc`, `lief`, `capstone`, etc. Make sure your
system has a C/C++ toolchain (`build-essential` on Debian/Ubuntu,
`xcode-select --install` on macOS) and `libffi-dev`. Still stuck?
Install one extra at a time to identify the offender.

### Does Deep View support Windows?

Partially. Core code runs on Windows, and platform-specific features
(WinPmem acquisition, ETW tracing, Windows memory plugins) are
windows-only. The CLI runs natively; install via `pip install -e ".[dev]"`
in an admin PowerShell and use `deepview doctor` to confirm coverage.

---

## Usage

### Does Deep View modify the source memory image?

No. Every `DataLayer` in the tree is effectively read-only — the
`write` method exists on the ABC but is implemented as `raise IOError`
on all in-tree layers. Unlocker decrypted-volume layers never write
back to the ciphertext. The netmangle engine writes to the network
only when explicitly enabled with `--enable-mangle` and an installed
NFQUEUE rule.

### How do I point Deep View at an existing dump?

```python
from deepview.memory.manager import MemoryManager
mgr = MemoryManager(context)
layer = mgr.open_layer(Path("/evidence/dump.raw"))   # format auto-detected
```

No acquisition happens. See [Recipe 01](cookbook/01-acquire-then-analyse.md)
step 2.

### What's the difference between `MasterKey` and `Passphrase`?

`MasterKey` carries raw key bytes and bypasses the KDF entirely —
`MasterKey.derive()` returns `self.key` unchanged. `Passphrase`
submits a KDF job via the offload engine; the result is the derived
cipher key.

Use `MasterKey` when you already have key material (memory extraction,
recovery blob, bcrypt-unwrapped). Use `Passphrase` when the user types
a password.

### How do I chain unlockers (LUKS inside VeraCrypt)?

Every decrypted volume is itself a `DataLayer`. Run the outer unlocker,
pass its result to the inner unlocker's `detect` + `unlock` — see
[Recipe 07](cookbook/07-nested-decrypt-luks-in-veracrypt.md).

### Why doesn't `deepview unlock auto` find my key?

Most likely causes:

1. The memory dump and the encrypted volume don't share a process.
   Unlocking BitLocker with memory from a Linux box won't work —
   need Windows memory from the same session.
2. The master key was paged out (cold-boot captures can miss it).
3. The orchestrator only tries master keys whose length matches the
   container's `dklen`. A 256-bit FVEK won't be tried against a volume
   expecting 128-bit AES.
4. `scan_keys=True` is the default *only* when `--memory-dump` is passed
   on the CLI. Pass `scan_keys=True` explicitly from Python.

### Can I unlock BitLocker without `pybde`?

No. `pybde` is the Python wrapper around Joachim Metz's `libbde` — the
de-facto open-source BitLocker implementation. Deep View's unlocker
delegates to it rather than reimplementing the format, which would be
a huge maintenance burden. Install via `pip install -e ".[containers]"`
(which pins `libbde-python`).

---

## Architecture

### Why is GPU offload not auto-enabled?

Two reasons:

1. **Detection cost.** Probing for OpenCL devices forks a subprocess in
   some drivers; we don't want that to happen implicitly on every
   `context.offload` first-access.
2. **Behaviour surprise.** GPU KDF kernels are not bit-identical to
   their CPU counterparts under all drivers. A subtle result
   difference would be confusing. Power users opt in with explicit
   `backend="gpu-opencl"`.

The OpenCL / CUDA backends *do* auto-register when they pass their own
`is_available()` probe — they're just not the default.

### What about Argon2id on GPU?

Honestly stubbed. Real Argon2id on GPU is hard (memory-hard ≠
compute-hard); reference kernels exist but performance wins are narrow
and driver-specific. See the "Trade-offs" section of
[`architecture/offload.md`](architecture/offload.md) for the current
status.

### How does plugin registration work?

Three tiers, discovered in order:

1. Built-in plugins registered via `@register_plugin` at import time
   (reached from `plugins/builtin/__init__.py`).
2. Entry-point plugins declared in third-party packages
   (`[project.entry-points."deepview.plugins"]`).
3. Directory scan of `config.plugin_paths` for `*.py` files.

Duplicates from later tiers are silently skipped, not overridden — by
design. See `PluginRegistry` in `plugins/registry.py`.

### Why two event buses?

The async `TraceEventBus` is *bounded* and *drops* on overflow — that
matches the real-time constraint of kernel probe output. The sync
core `EventBus` has no such constraint. Keeping them separate means
the high-rate tracer never back-pressures the dashboard, the replay
recorder, or anything else on the core bus.

### How do I add a new filesystem adapter?

Subclass `Filesystem` (see
[`interfaces/filesystem.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/interfaces/filesystem.py)),
implement `probe` + `list` + `stat` + `open` + `read`, and register it
with `register_filesystem("myfs", MyFilesystem)` from your
`filesystems/registry.py` entry. See
[`guides/extending-deepview.md`](guides/extending-deepview.md).

---

## Security

### Why does `deepview remote-image dma-tb` need root?

Because it talks to Thunderbolt / PCIe / FireWire devices directly,
which requires `CAP_SYS_RAWIO` on Linux. There's no way around that —
PCIe configuration-space reads need kernel cooperation. The macOS and
Windows providers have their own elevation stories (SIP authorization
on macOS, Administrator on Windows).

### What's the authorization-statement gate about?

Every dual-use subcommand (`remote-image *`, `netmangle run`,
`unlock auto --memory-dump`) requires the operator to explicitly
attest authorization via `--authorization-statement=env:NAME` or
`file:/path/to/statement.txt`. The gate is mechanical — it prints
a 5-second banner before any traffic — but it's there so there's
always a paper trail. See
[`cli/commands/remote_image.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/cli/commands/remote_image.py).

### How does netmangle avoid accidentally breaking traffic?

The engine is fail-open: any exception during match or action
evaluation returns `ACCEPT`. `--dry-run` forces every verdict to
`ACCEPT` regardless of the matched action. The NFQUEUE jump rule is
never installed unless `--install-iptables` is passed. See the
netmangle section of `CLAUDE.md`.

### Are passphrases ever written to disk?

Not by Deep View. The CLI takes passphrases from interactive prompts
(hidden echo via `getpass`) or from environment variables. The offload
engine pickles the passphrase when a job crosses a process boundary —
that memory is reclaimed by the worker's exit. If this is a hard
threat model concern, use process isolation on the host.

---

## Troubleshooting

### `deepview doctor` reports a subsystem as unavailable. What now?

Every "unavailable" line is followed by the reason (missing module,
failed probe, bad capability). The fix is usually to install the
matching extra — see [`reference/extras.md`](reference/extras.md) for
the matrix. For deeper diagnosis see
[troubleshooting](troubleshooting.md).

### My ruleset doesn't match events. What's wrong?

Check:

1. The rule's `match:` clause parses — copy-paste into
   `deepview.tracing.filters.parse_filter()` and inspect.
2. Events are actually reaching the classifier. Subscribe to
   `MonitorEvent` on the tracer bus for a moment and confirm.
3. Classification is running — if the classifier's task died,
   look at its internal log; see
   [troubleshooting](troubleshooting.md#classifier-silent).

### MkDocs build fails. Where do I start?

See [troubleshooting: MkDocs build errors](troubleshooting.md#mkdocs-build-errors).

---

## Contributing

### How do I run the tests?

```bash
pip install -e ".[dev]"
pytest
pytest -m "not slow and not integration"
```

Some tests need optional extras; tests that need root skip by default.
See `CONTRIBUTING.md` for the marker list.

### Are there style conventions?

- `ruff check src tests` — py310 target, 100-char lines.
- `mypy src` — strict mode.
- `from __future__ import annotations` everywhere.
- PEP 604 unions (`X | None` over `Optional[X]`).
- Dataclasses over ad-hoc dicts.

The existing `storage/containers/unlock.py` and `offload/engine.py`
modules are good style references.

### Where do docs live, and how do I preview them?

All docs are under `docs/` as Markdown. Preview with:

```bash
pip install -e ".[docs]"
mkdocs serve
```

Slice 1 owns `mkdocs.yml`; when you add a new page, the nav update
happens in the same slice as the content — not here.

### How do I add a new cookbook recipe?

Drop an `NN-kebab-case.md` file into `docs/cookbook/` (50-150 lines),
add a row to `docs/cookbook/index.md`, and submit. Each recipe should
be self-contained, cross-link generously, and declare its extras in a
callout at the top.
