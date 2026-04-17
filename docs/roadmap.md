# Roadmap

This roadmap records what Deep View ships today, what is partial and
under active work, what is a candidate for future releases, and what
is explicitly **out of scope**. The further right a feature sits in
this document, the less certain its delivery.

> **Note on promises.** Items under [In progress](#in-progress) are in
> the codebase today in a limited form; items under [Roadmap (v0.3)](#roadmap-v03-candidates)
> and [Roadmap (v1.0)](#roadmap-v10) are *candidates*, not commitments.
> We mark them as such deliberately — forensic tooling ages badly when
> shipped against a deadline.

## Stable (v0.2)

The following subsystems are shipped, documented, and covered by the
test suite. Breaking changes within a minor version require an ADR.

| Subsystem | Status | Notes |
|-----------|--------|-------|
| `deepview.core` (AnalysisContext, EventBus, Config, Platform) | Stable | The pydantic-settings config tree is frozen for v0.x; additive changes only. |
| `deepview.plugins` (registry, three-tier discovery) | Stable | `@register_plugin` decorator stable; entry-point contract stable. |
| Memory acquisition (LiME / AVML / WinPMem / OSXPmem / live `/dev/mem`) | Stable | Format detection uses [ADR 0009](adr/0009-dump-format-detection-by-magic-then-extension.md). |
| Memory parsers (raw, LiME, ELF core, crashdump, hibernation) | Stable | All five round-trip-tested in `tests/unit/test_memory/formats/`. |
| Memory analysis (Volatility 3 engine + MemProcFS engine) | Stable | Volatility 3 used as a library, not a subprocess. |
| Page-table translation + virtual layer | Stable | Composed atop the `DataLayer` abstraction ([ADR 0001](adr/0001-data-layer-composition-over-inheritance.md)). |
| TCP/IP reconstruction (read-only, from memory image) | Stable | Distinct from the live NFQUEUE `networking` engine. |
| Tracing (eBPF / DTrace / ETW providers) | Stable | `TraceEventBus` async fan-out with drop-on-overflow semantics. |
| Filter DSL + `FilterPlan` compilation into `KernelHints` | Stable | |
| Classification (YAML rulesets + anomaly bridge) | Stable | Builtin rules live under `classification/builtin_rules/`. |
| Replay (session recorder + SQLite store + replayer) | Stable | Replayed events are indistinguishable from live. |
| Inspect primitives (ProcessInspector, LiveProcessLayer, FileInspector, NetInspector) | Stable | Live `/proc/[pid]/mem` exposed as a `DataLayer`. |
| Instrumentation (Frida engine + static reassembly via LIEF/Capstone) | Stable | |
| VM introspection (QEMU/KVM, VirtualBox, VMware) | Stable | Snapshot and state helpers. |
| Disassembly (Capstone, Ghidra via pyhidra, Hopper) | Stable | `requires_ghidra` / `requires_hopper` markers gate tests. |
| Scanning (YARA, string carver, IoC engine) | Stable | |
| Detection (anti-forensics, injection, encryption-key, anomaly) | Stable | See [ADR 0007](adr/0007-encryptionkeyscanner-feeds-unlocker.md). |
| Reporting (HTML/Markdown/JSON, ATT&CK Navigator, STIX 2.1) | Stable | |
| CLI dashboard (multi-panel Rich) | Stable | Layouts: `network`, `full`, `minimal`, `mangle`. |
| NFQUEUE packet-mangling engine (`deepview netmangle`) | Stable | Fail-open on error; root + `--confirm` required. |
| Offload engine (thread + process backends) | Stable | Default is `process`; see [ADR 0004](adr/0004-process-pool-default-offload-backend.md). |
| Storage stack (filesystems / FTL / ECC / partitions / encodings / auto) | Stable | Composition model per [ADR 0001](adr/0001-data-layer-composition-over-inheritance.md). |
| Container unlock orchestrator (LUKS1/LUKS2 pass + BitLocker + VeraCrypt AES-XTS) | Stable-ish | See the partial matrix under [In progress](#in-progress). |
| Remote memory acquisition (SSH/DD, TCP, UDP, IPMI, AMT, DMA via leechcore) | Stable | Fail-secure defaults per [ADR 0006](adr/0006-fail-secure-remote-acquisition.md). |

## In progress

Features in the codebase today in a limited or experimental form.
These are landing incrementally; the sub-bullets record where each is
on the completion curve.

### ZFS filesystem adapter — **probe-only**

`deepview.storage.filesystems.zfs` detects a ZFS vdev label (magic and
version) and reports pool name, size, and vdev topology. **Read paths
are not implemented.** Attempting to list files raises
`NotImplementedError`. The blocker is the absence of a robust, portable
ZFS read library in Python; binding `libzfs` via `cffi` is on the v0.3
candidate list.

- Architecture: [`architecture/storage.md`](architecture/storage.md)
- Tracking work: probe → pool enumeration → dataset walk → block
  pointer resolution → file bytes.

### F2FS filesystem adapter — **marginal**

Adapter is wired and registered (`StorageManager.register_filesystem("f2fs",
F2FSAdapter)`) but depends on `pyfsf2fs`, which is immature —
read-only, no extent-tree walks, no inline-data support, no
compression. Small images work; real-world F2FS images frequently
return partial results.

- Users can still enumerate directory structure on simple images.
- Polishing depends on upstream `pyfsf2fs` or a replacement library
  (see v0.3 candidates).

### Xpress-Huffman decompression — **partial**

Used by the Windows hibernation-file parser. Block-level decoder
works for the common cases; a minority of blocks fail on edge
variants of the bit-stream format seen in Windows 11 24H2 images.
Symptoms are a specific `XpressDecodeError` at a known offset; the
hibernation parser surfaces the error and continues with the
remaining pages.

### WKdm decompression — **stubbed**

Apple's WKdm algorithm appears in swap-compressed pages on macOS.
The stub recognises the magic and reports "compressed page detected,
decompression not implemented" so analysts know data is there. A
full decoder is ~500 lines of bit-packing; we want to land it with a
corpus of known pages to test against.

### LUKS2 unlock — **JSON-parsed but not round-trip-tested**

The LUKS2 unlocker parses the JSON metadata header, selects the
active keyslot, dispatches KDF work through the offload engine, and
decrypts master-key material. It works on every image we've tested.
**It has not been round-trip-tested** against a matrix of cryptsetup
versions and parameter combinations. Until we build that matrix, we
recommend double-checking important LUKS2 unlocks with a second
tool.

- LUKS1 is fully tested.
- Memory-extracted master keys ([ADR 0007](adr/0007-encryptionkeyscanner-feeds-unlocker.md))
  are the fastest path and are well-tested.

### VeraCrypt — **AES-XTS only**

Only the AES-XTS cipher is wired. Selecting Serpent-XTS or
Twofish-XTS (or any cascade) raises `NotImplementedError` with a
message naming the missing primitive. AES-XTS covers the dominant
real-world case, but operators working with serpent-loyalist threat
actors should use an external tool until this lands.

- Hidden-volume detection (`try_hidden=True`) works for AES-XTS.
- FileVault 2 is also unfinished — detect-only for now.

## Roadmap (v0.3) candidates

Candidates the team is actively considering for the next minor
release. These are not commitments; implementation order is driven
by operator demand and external library maturity.

### Real ZFS read support

Binding `libzfs` through `cffi` to get at block-pointer resolution,
then layering on top of it a `DataLayer`-shaped adapter so the rest
of the storage stack composes unchanged. A pure-Python read-only
alternative (parsing uberblocks + dnode tree + block pointers
directly) is also on the table as a way to avoid the native
dependency, at the cost of significant implementation work.

**Target:** read one file out of a single-vdev single-dataset pool
end-to-end. Multi-vdev / RAID-Z comes later.

### GPU Argon2id through OpenCL / CUDA backends

The offload engine's GPU backends currently carry PBKDF2 and a few
hashing kernels. Argon2id is memory-hard and a good GPU candidate
for the large-memory variants. Target is a kernel that matches or
beats libsodium's CPU reference implementation on a mid-range
consumer GPU.

### gRPC remote-worker backend

A `RemoteBackend` subclass of `OffloadBackend` that dispatches jobs
to a worker pool over gRPC with TLS and mutual auth. Worker processes
run the same backend stack as the local engine, enabling cluster
offload for KDF attacks during authorised assessments.

Depends on [ADR 0006](adr/0006-fail-secure-remote-acquisition.md)-level
fail-secure defaults for the client and mutual TLS on the server.

### Sphinx autodoc mirror

An opt-in `mkdocstrings` integration that renders API reference from
existing docstrings. Complements (does not replace) the hand-written
reference pages. See [ADR 0003](adr/0003-mkdocs-over-sphinx.md) —
this is the "if we add autodoc later" path.

### F2FS polish

Either:

- Track the `pyfsf2fs` upstream into maturity and contribute fixes,
  or
- Port the relevant pieces of `f2fs-tools` to pure Python (extent
  tree, inline data, compression).

Either path is ~2 weeks of focused work.

### Native APFS encryption passthrough

APFS volume-level encryption (FileVault 2's modern form) is
extremely close to APFS itself; rather than treat the container as
an opaque encrypted blob, we can walk the APFS B-tree to locate the
encryption extent records and decrypt selectively. This is a big
architectural change because APFS is already a filesystem adapter;
the container unlock story would route through the filesystem
instead of through `UnlockOrchestrator`.

**Open design question:** does this fit the orchestrator's
`Unlocker` ABC or does it need a new `VolumeEncryption` interface?
An ADR will capture whichever choice we make.

### More Volatility 3 shims

Expose additional Volatility 3 plugins (network sockets, kernel
modules on Windows, registry analysis) as first-class
`DeepViewPlugin` wrappers. The shim pattern is stable; this is
expansion work, not new architecture.

### LUKS2 round-trip matrix

Build a CI job that creates a LUKS2 container with a given
cryptsetup version and a matrix of `--cipher` / `--hash` /
`--pbkdf` / `--iter-time` combinations, then asserts the Deep View
unlocker opens each one. Promote LUKS2 out of "in progress" when
the matrix is green.

### Windows-live acquisition hardening

The WinPMem provider works but has paper cuts around WoW64 and
kernel CFG on newer Windows 11 builds. Candidate work includes
shipping a signed driver (likely out of reach without a vendor
partnership) or coordinating with the WinPMem project on a
fallback path.

### Additional unlockers

- Hashicorp Vault transit backend (for lab environments where
  encryption keys are Vault-held).
- TPM-sealed LUKS keyslots.
- BitLocker recovery-key path (currently only passphrase and FVEK
  from memory).

### Additional filesystem adapters

Btrfs, XFS `reflink` awareness, and refs (Microsoft ReFS) at the
"adapter covering common paths" level. None are blocked; all are
size-of-work dependent.

## Roadmap (v1.0)

The 1.0 release criterion is a combination of API stability and
real-world battle-testing. Candidates, not commitments.

- **All public ABCs frozen.** `DataLayer`, `Filesystem`,
  `FTLTranslator`, `ECCDecoder`, `MemoryAcquisitionProvider`,
  `OffloadBackend`, `Unlocker`, `KeySource`, `DeepViewPlugin`,
  `Scanner`, `Tracer`, `Instrumentor`, `VMConnector`,
  `Disassembler`, `Acquisition`, `Renderer`, `Analysis`. Changes
  after 1.0 are new ABCs; existing ones are preserved or
  deprecated on a documented schedule.
- **Test coverage above 80% line coverage in `src/`.** Per
  subsystem, not averaged.
- **Real-world battle-testing.** Operators using Deep View in at
  least three substantial investigations and providing public or
  private feedback. We will not reach 1.0 on lab testing alone.
- **Stable plugin API.** Every public hook in the plugin system
  (decorators, base classes, entry-point naming) is final; a plugin
  that works on 1.0 continues to work on 1.x.
- **Security-disclosure process documented** and tested via at
  least one real advisory handled through it.
- **Reproducible Mayflower build.** A pinned dependency set and a
  reproducible docker image so a given Deep View release produces
  identical analysis output across machines.
- **Documentation coverage.** Every stable subsystem has an
  architecture page, a reference page, and at least one guide. ADR
  count reflects the stable decisions.

## Out of scope

Things Deep View **will not become**, listed explicitly so no one
spends time proposing them.

### GUI / desktop application

Deep View is a CLI + library. A GUI is a different product, with a
different UX budget and different maintenance cost. If a GUI emerges
in this ecosystem it will be a separate project consuming Deep View
as a library.

Tools the GUI-minded user should look at instead: Volatility Workbench,
Autopsy, FTK Imager. Deep View is designed to be embedded inside or
alongside them, not to compete.

### Distributed agent fleet (Velociraptor-style)

Deep View's remote acquisition is point-to-point, operator-initiated,
dual-use-gated ([ADR 0006](adr/0006-fail-secure-remote-acquisition.md)).
It is explicitly *not* trying to be Velociraptor or Kolide — a
persistent agent mesh with centralised C2 and hunt orchestration.
That is a different class of tool with different safety trade-offs.
If you need it, use Velociraptor.

### Cloud SaaS / hosted analysis

We do not intend to run a hosted analysis service. Forensic images
contain whole-host secrets; we do not want to build the multi-tenant
isolation story required to handle them safely, and running a
service would conflict with the project's "operator runs it locally"
ethos.

### SIEM replacement

The classification subsystem + dashboard are for triage and live
trace analysis, not for being the primary SIEM for an organisation.
Deep View does not retain events for months, does not handle log
shipping from hundreds of hosts, and is not building a query
language for historical events beyond the replay / session store.
Tools like Splunk, Elastic SIEM, Chronicle, and Panther cover that
territory.

### Licensed commercial extensions

There will not be a "Pro" tier, a "Cloud" tier, or a licence server.
The project is open-source end-to-end.

## Conventions

A few meta-rules for this document itself:

- **Roadmap entries are not promises.** Every item here is an
  "intent if nothing changes." Investigation priorities shift when
  the world shifts; the operators using Deep View set the pace.
- **Removals get ADRs.** If a stable feature is retired, it gets an
  ADR explaining why, with a migration note in the changelog.
- **New subsystems get ADRs.** Not every architectural choice, but
  every non-obvious one. If the answer to "why is it shaped like
  that?" is non-trivial, write it down.
- **Partial features are honest about their partiality.** The
  [In progress](#in-progress) section is deliberately explicit about
  what doesn't work. Forensic tooling that overpromises is worse
  than useless.
- **Out-of-scope items stay out.** When a contributor proposes one,
  point them here and invite them to discuss the trade-off.

## Related reading

- [Architecture Decision Records](adr/index.md) — the ten ADRs
  that underpin this roadmap.
- [Architecture overview](overview/architecture.md) — the current
  system as built.
- [Storage architecture](architecture/storage.md),
  [offload architecture](architecture/offload.md),
  [containers architecture](architecture/containers.md), and
  [remote acquisition architecture](architecture/remote-acquisition.md)
  — the four new subsystems referenced heavily above.
