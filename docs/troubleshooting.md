# Troubleshooting

Concrete problem → diagnosis → fix entries for the most common snags.
For general questions see [FAQ](faq.md); for architecture reasoning see
the `architecture/` tree.

!!! tip "First step: run `deepview doctor`"
    Almost every "X is missing" problem has a one-line diagnosis in
    `deepview doctor`'s output. Run it before anything else.

---

## Installation & imports

### `deepview doctor` reports `volatility3` as missing

**Diagnosis.** The base install skips `[memory]`. `MemoryManager`
imports and probes `VolatilityEngine` on init; when `volatility3` is
absent the engine prints a debug line and is left out of
`_engines`.

**Fix.**
```bash
pip install -e ".[memory]"
deepview doctor     # should now show volatility: available
```

### `ImportError: No module named 'bcc'` on Linux

**Diagnosis.** `[linux_monitoring]` not installed, or `bcc`'s Python
binding wasn't wired into this Python environment. BCC ships as a
system package on most distros but its Python binding needs symlinking
into your venv's `site-packages`.

**Fix.** On Debian/Ubuntu:
```bash
sudo apt install bpfcc-tools python3-bpfcc
# Then symlink or pip-install into the venv
pip install -e ".[linux_monitoring]"
```

If you still see the import error with a venv, check
`ls /usr/lib/python3/dist-packages/bcc`.

### `pybde` won't install on macOS arm64

**Diagnosis.** `libbde` upstream ships x86_64 wheels only; arm64 users
need to build from source.

**Fix.**
```bash
brew install libbde          # or build upstream from source
pip install --no-binary=libbde-python libbde-python
```

Then `pip install -e ".[containers]"` should pick it up.

### Tests fail with `pytsk3 not installed`

**Diagnosis.** A test is marked `requires_extra="storage_tsk"` but the
extra isn't installed. The `requires_extra` marker is registered in
`pyproject.toml` but many CI lanes run the base extras only.

**Fix.**
```bash
pip install -e ".[storage_tsk]"
pytest tests/unit/test_storage/test_tsk_fs.py
```

Or skip them entirely: `pytest -m "not requires_extra"`.

---

## Unlock paths

### Container unlock fails with `ContainerUnlockFailedEvent reason='all candidate keys exhausted'`

**Diagnosis.** The orchestrator tried every candidate in
`(master_keys, keyfiles, passphrases)` order and none succeeded. The
event carries the `format` and `layer` but not the individual attempts
(by design — candidate material is sensitive).

**Fix — checklist.**

1. Confirm candidate material was actually collected:
   ```python
   print(len(ctx.unlocker._collect_memory_keys()))
   ```
   Zero means `EncryptionKeyScanner` found nothing; check that the
   memory dump is registered in `ctx.layers` and is non-empty.
2. Check key-length filtering: `UnlockOrchestrator._expected_key_length`
   returns `header.kdf_params["dklen"]`; candidates with the wrong
   length are skipped silently.
3. Enable verbose logging: `DEEPVIEW_LOG_LEVEL=DEBUG deepview unlock
   auto ...` — each adapter logs the exception body for failed
   attempts.

### VeraCrypt unlock takes forever, seemingly hangs

**Diagnosis.** VeraCrypt probes every KDF × cipher-cascade
combination. Each attempt is a full PBKDF2 derivation with the
container's iteration count (default 500 000). With PIM > 0 this gets
much worse. That's expected, not broken.

**Fix.** Pass `--pim` if you know it. Use `--master-key-hex` to skip
the KDF entirely when you have the key. Ensure `context.offload` has a
reasonable `process` pool size (default = CPU count).

### `deepview unlock auto` returns 0 unlocked layers

**Diagnosis.**

- No container was detected on the image. Every `Unlocker.detect`
  returned `None` silently.
- Memory scanning was off. `scan_keys=True` is the default only when
  `--memory-dump` is passed; programmatic callers must set it
  explicitly.
- Passphrase list was empty. `auto_unlock(..., passphrases=())` won't
  try the `Passphrase` code path at all.

**Fix.** Use `deepview storage info IMAGE` to see what adapters
match the image at all. If none do, the image may be plain-text or use
an unsupported format (e.g. CoreStorage legacy, LUKSv0, etc.).

---

## Remote acquisition

### DMA Thunderbolt acquisition aborts before reading anything

**Diagnosis.** The provider checks IOMMU state on startup. On modern
Linux (kernel ≥ 5.4) with `iommu=pt` in the cmdline, DMA to
arbitrary physical addresses is blocked and the provider aborts
rather than silently returning garbage.

**Fix.**

- **Authorized lab use:** reboot with `iommu=off` or `intel_iommu=off`
  in the kernel cmdline; confirm with
  `dmesg | grep -i iommu`.
- **Vendor-specific:** on some systems Thunderbolt security mode must
  be set to "None" or "User" in firmware; "SecureConnect" blocks DMA
  peripherals by default.

Never disable IOMMU on production hosts.

### `deepview remote-image ssh` refuses with "ssh transport with --require-tls needs --known-hosts"

**Diagnosis.** TLS-equivalent verification for SSH is the
`known_hosts` pin. The CLI refuses to connect without it unless you
explicitly opt into `--no-require-tls`.

**Fix.** Generate a known_hosts file:
```bash
ssh-keyscan -t ed25519 host.example.com > /secure/known_hosts
deepview remote-image ssh --host host.example.com \
    --known-hosts /secure/known_hosts ...
```

Do not pass `--no-require-tls` on real captures.

### Remote acquisition stalls midway through

**Diagnosis.** Network hiccup or remote-side memory read hit a
non-physical region. The provider publishes
`RemoteAcquisitionProgressEvent` every N MiB — if progress stops, the
underlying `dd` / streamer has blocked.

**Fix.** Subscribe to progress events (see
[Recipe 11](cookbook/11-build-remote-endpoint-config.md)) and emit a
watchdog. Increase the transport timeout via `--extra timeout=300`.
When the remote `dd` itself hangs, check the target's kernel log
for MCE / EDAC errors.

---

## Tracing & classification

### Classifier silent — no `EventClassifiedEvent`s appear

**Diagnosis.** Order of operations is likely:

1. You called `ctx.events.subscribe(...)` *before* starting the
   classifier, so the sync bus has handlers but the classifier hasn't
   published anything yet.
2. Tracer started but produces zero events. The filter is too narrow
   or the probe isn't attached.
3. The classifier task died. Its exception is logged to the
   `classification.classifier` logger.

**Fix.** Tail the Deep View log
(`~/.deepview/logs/deepview.log` by default) for
`classifier_task_exited`. If the tracer is the problem, run
`deepview trace --probe raw_syscalls --filter ""` to confirm events
flow at all.

### Trace events are being dropped

**Diagnosis.** The async `TraceEventBus` has bounded per-subscriber
queues (128 by default). On overflow it increments
`subscription.dropped_count` and moves on. The firehose (raw_syscalls
with no filter) routinely overwhelms the poll thread.

**Fix.** Narrow the filter at the probe, not the subscriber. For
PID-specific watches use `filter: pid == 1234` so the kernel-side
predicate short-circuits irrelevant events.

---

## Storage stack

### `DeepViewConfig.load` raises "config file is symlink"

**Diagnosis.** `_validate_config_file` in `core/config.py` refuses
symlinked config files because a symlink-follow during load is a
time-of-check-to-time-of-use vector. This is intentional — don't bypass
it.

**Fix.** Either replace the symlink with the real file
(`cp -L ~/.deepview/config.toml ~/.deepview/config.toml.real && mv
~/.deepview/config.toml.real ~/.deepview/config.toml`) or point
`$DEEPVIEW_CONFIG` at a non-symlinked path.

### Filesystem mount fails with "no adapter recognised the layer"

**Diagnosis.** `StorageManager.open_filesystem` iterated every
registered adapter and every `probe()` returned `False`. Common
reasons: the layer is encrypted (see the unlock cookbook); the
partition offset is wrong (try `parse_partitions` first); the
filesystem is one Deep View doesn't ship an adapter for.

**Fix.** Run `deepview storage info NAME` for the layer to see which
adapters were tried. For unsupported filesystems install the TSK
fallback (`[storage_tsk]`) and retry — `pytsk3` covers most exotic
formats.

### ECC-wrapped NAND reads return garbage

**Diagnosis.** The spare layout is almost certainly wrong. A
misaligned ECC region feeds random bytes into `BCHDecoder`, which
happily "corrects" them to arbitrary values.

**Fix.** Switch to a vendor-specific layout if you know the chip:
```python
from deepview.storage.ecc.layouts import samsung_klm, toshiba_tc58
geom = replace(geom, spare_layout=samsung_klm(spare_size=geom.spare_size))
```
If the chip is unknown, scope the spare layout from the first block's
ONFI parameter page rather than guessing.

---

## Docs & recordings

### MkDocs build fails with "mermaid: parse error"

**Diagnosis.** `mermaid2` is strict about syntax — a stray comma or
parenthesis in a node label breaks the parser.

**Fix.**

1. Paste the offending block into <https://mermaid.live> to isolate
   the syntax error; fix it there first.
2. Upgrade `mkdocs-mermaid2-plugin` to the pinned version in
   `pyproject.toml [docs]` — older versions ship bundled mermaid.js
   that disagrees with 10.x syntax.
3. Run `mkdocs build --strict` locally; CI runs with `--strict` so
   the failure reproduces offline.

### Asciinema cast doesn't render in README on GitHub

**Diagnosis.** GitHub Markdown doesn't run the asciinema player — only
MkDocs + the `asciinema-player` plugin does. For the README we embed
the SVG export.

**Fix.**
```bash
svg-term --in docs/casts/00-doctor.cast \
         --out docs/casts/00-doctor.svg \
         --window --term iterm2
```
Then reference the SVG from the README.

### MkDocs build errors

The two most common:

- **"nav not found"** — a page was added but `mkdocs.yml`'s `nav:`
  block wasn't updated. Slice 1 of the doc plan owns `mkdocs.yml`; new
  pages live in the tree but may not appear in the sidebar until the
  nav is updated.
- **"file referenced but not found"** — a cross-link resolves outside
  `docs/`. Use relative paths within `docs/` only.

Always re-run with `mkdocs build --strict` — it fails fast on
broken links, missing nav entries, and mermaid parse errors.
