# 0005. Pluggable `Unlocker` via the `UNLOCKER` module attribute

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Container unlock in Deep View is orchestrated by
`UnlockOrchestrator` (see `src/deepview/storage/containers/unlock.py`). It
holds a registry of `Unlocker` adapters — LUKS, BitLocker, VeraCrypt,
FileVault 2 in later slices — and tries each one against a candidate
`DataLayer`.

Each adapter lives in its own module (e.g.,
`deepview.storage.containers.luks.adapter`). We needed a way for the
orchestrator to discover and load them without hard-coding an import
list in `UnlockOrchestrator.__init__`, because:

- The matrix of adapters is open-ended; third-party packages may ship
  unlockers for niche formats.
- Every adapter pulls a separate optional dependency
  (`cryptsetup-python`, `dislocker`, `pycryptodome`, etc.), and per
  ADR 0002 we must not import adapter modules unless asked.
- The `@register_plugin` mechanism in the plugins subsystem already
  exists, but applies to `DeepViewPlugin` subclasses — unlockers are a
  different interface and we did not want to overload the plugin
  machinery.

## Decision

**Every unlocker module exposes a module-level `UNLOCKER` attribute
pointing at its adapter class.** The orchestrator discovers adapters by
walking a fixed list of module dotted-names (for built-ins) and a
configurable list of third-party entry points, then reads the `UNLOCKER`
attribute from each successfully imported module.

```python
# src/deepview/storage/containers/luks/adapter.py
class LUKSUnlocker(Unlocker):
    ...

UNLOCKER: ClassVar[type[Unlocker]] = LUKSUnlocker
```

Discovery is lazy: `UnlockOrchestrator` imports adapter modules on
first use, catches `ImportError` (per ADR 0002), and silently skips
adapters whose optional dependency is absent.

Third-party adapters declare themselves via
`[project.entry-points."deepview.unlockers"]` in their own
`pyproject.toml`; the entry-point target is the module containing
`UNLOCKER`.

## Consequences

### Positive

- **Uniform discovery surface.** One attribute name, one ABC, one
  registry mechanism. Anyone writing a new unlocker copies an existing
  module and changes the class.
- **Lazy and safe.** An unlocker whose backing library is absent
  raises `ImportError` on its own import; the orchestrator catches it
  and moves on. The user sees "LUKS unlocker unavailable" rather than
  a crash.
- **Decoupled from the `@register_plugin` system.** The plugin registry
  has three discovery tiers and its own semantics (see CLAUDE.md) that
  don't map cleanly onto unlockers. Keeping unlockers separate avoids
  entangling the two.
- **Third-party-extensible.** Entry-point discovery is standard Python
  packaging; no Deep View-specific plumbing is required from the
  consumer.
- **Statically analysable.** `UNLOCKER: ClassVar[type[Unlocker]]` is a
  typed module-level symbol; mypy verifies the contract at the
  publisher side.

### Negative

- **Convention not enforced at runtime.** A module missing the
  `UNLOCKER` attribute produces a clear `AttributeError` at discovery,
  not at import. We log a helpful message and continue.
- **One adapter per module.** If a single module wanted to export two
  unlockers (e.g., LUKS1 and LUKS2), it would have to pick one for the
  canonical attribute. In practice each format is its own module, so
  this has not been a problem.
- **Duplicate discovery paths.** Built-ins use a hard-coded list;
  third-parties use entry points. We keep both because the built-in
  list is useful as explicit documentation of first-party support.

### Neutral

- The decision applies to unlockers specifically. Filesystems, FTL
  translators, and ECC decoders have their own registries
  (`StorageManager.register_filesystem` etc.) that are called from a
  `register_all()` function. Different enough to warrant its own
  pattern, similar enough in spirit.

## Alternatives considered

### Option A — Reuse `@register_plugin`

Make every unlocker a `DeepViewPlugin` and dispatch via the plugin
registry. Rejected because:

- `DeepViewPlugin.run()` returns a `PluginResult`, which is the wrong
  return shape for "unlock this layer; return a `DecryptedVolumeLayer`".
- The plugin registry's three-tier discovery semantics and duplicate
  handling (first-tier wins, later tiers are logged-and-skipped) are
  intentional for plugins but not what we want for unlockers (where a
  third-party adapter for a new format is additive, not a conflict).

### Option B — Class decorator `@register_unlocker`

Mirror the plugin decorator. Rejected because the decorator sets
module-level state as a side effect of import, which then requires the
orchestrator to know *which modules to import* — which is the same
discovery problem we started with. The `UNLOCKER` attribute avoids the
side-effect-at-import smell.

### Option C — Explicit list passed to the orchestrator

`UnlockOrchestrator(unlockers=[LUKSUnlocker, BitLockerUnlocker, ...])`.
Rejected for built-ins because it pushes discovery into callers; every
CLI command and every test would need to know the current list. For
advanced callers who *want* to override the set, the orchestrator does
accept an explicit `unlockers=` keyword; the default falls back to
auto-discovery.

### Option D — Setuptools entry points only

Skip the built-in list; even LUKS would be an entry point. Rejected
because the built-ins would become invisible in the codebase — a new
contributor would have no single place to see "these are the unlockers
Deep View ships with". The dual path (hard-coded list for built-ins,
entry points for third parties) keeps the first-party story discoverable.

## References

- Source: `src/deepview/storage/containers/unlock.py` — the
  orchestrator.
- Source: `src/deepview/interfaces/...` — the `Unlocker` ABC (companion
  interface).
- Architecture page: [`../architecture/containers.md`](../architecture/containers.md)
- Related ADR: [0002 — Lazy imports](0002-lazy-import-optional-deps.md)
- Related ADR: [0007 — EncryptionKeyScanner feeds the unlock
  orchestrator](0007-encryptionkeyscanner-feeds-unlocker.md) — the
  main consumer of this registry.
