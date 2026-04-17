# 0007. `EncryptionKeyScanner` feeds the unlock orchestrator

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Deep View's memory-analysis stack includes an `EncryptionKeyScanner`
(`src/deepview/detection/`) that walks a memory image or a live
`DataLayer` looking for symmetric-key candidates — AES key schedules,
LUKS master keys cached in kernel `crypt_setup` slabs, BitLocker FVEK
cached in `fvevol.sys` structures, and similar signatures. The scanner
has traditionally emitted findings as artifacts, to be viewed in a
report.

Separately, the container-unlock orchestrator
(`src/deepview/storage/containers/unlock.py`) tries to open encrypted
volumes using three kinds of input, documented in the module docstring:

1. `MasterKey` candidates (cheap — direct symmetric decrypt).
2. `Keyfile` candidates.
3. `Passphrase` candidates (expensive — KDF dispatched through
   `OffloadEngine`).

Scanned memory keys are the canonical source of `MasterKey` candidates.
Without a path from scanner to unlocker, the two subsystems duplicated
work: an operator would run the scanner, note the hex keys, and hand
them to the unlocker CLI.

## Decision

**Keys discovered by `EncryptionKeyScanner` flow into the unlock
orchestrator as `MasterKey` candidates, automatically and with
provenance.** The wiring uses the event bus (per ADR 0008): the scanner
publishes `EncryptionKeyFoundEvent` onto `context.events`; the
orchestrator subscribes and maintains an in-memory pool of
`MasterKey(bytes=..., source=..., provenance=...)` candidates.

When the orchestrator is asked to unlock a container, it:

1. Tries every pooled `MasterKey` first (cheap: one AES decrypt each).
2. Tries explicit `Keyfile` paths from the CLI / config.
3. Only if neither works, falls back to `Passphrase` attempts through
   the offload engine.

The `MasterKey.provenance` carries the memory address, process name /
pid (when known), and scanner signature name that produced the key, so
a later report can trace "LUKS volume /dev/sdb was opened via FVEK
extracted from pid 812 (gnome-disks) at offset 0x7f2a1b00."

## Consequences

### Positive

- **Dramatic speedup for live triage.** An analyst with a live memory
  image avoids every KDF iteration. A modern Argon2id-protected
  LUKS2 header that would take minutes to brute-force opens in
  milliseconds if the master key is in kernel memory.
- **Provenance preserved.** The key did not come from the user, and
  the report says so.
- **Zero coupling between scanner and unlocker modules.** Scanner
  publishes; orchestrator subscribes. Neither imports the other.
- **Works for replay.** Recorded sessions re-emit the scanner event,
  and the orchestrator behaves identically on replay — auditable
  reproduction.
- **Matches operator intuition.** "I found a key — try it" is what a
  human analyst would do manually.

### Negative

- **Pool size must be bounded.** A noisy scanner can publish thousands
  of candidates; trying each on every container would cost a lot of
  AES operations. The orchestrator bounds the pool (LRU, default 4096
  candidates) and deduplicates by key bytes.
- **False positives cost time.** Every pooled key is tried against
  every container; a wrong key returns a failed-MAC almost
  immediately, but 1000 wrong keys × N containers has measurable
  cost. Acceptable in practice, but worth watching.
- **Tight coupling to the event-bus contract.** If the event schema
  changes, both ends must update in lockstep. We mitigate with typed
  Event classes in `core/events.py` and a mypy-strict baseline
  (ADR 0010).
- **Security surface.** Master keys now sit in the orchestrator's
  process memory in addition to whatever kernel structure held them.
  The Python process is already privileged (it reads memory images),
  so this does not cross a trust boundary — but it does widen the
  window in which a process crash could leak keys into a core dump.
  We recommend disabling core dumps on the analysis host.

### Neutral

- The feature is on by default; users who want to disable it set
  `config.storage.containers.use_scanned_keys = False`.
- An explicit `MasterKey` supplied on the CLI ranks above pooled
  candidates, so operator-provided keys are always tried first.

## Alternatives considered

### Option A — No automatic wiring; require explicit `--use-memory-keys`

A CLI flag the operator must remember. Rejected because the primary
use case is "I have a memory image; please unlock this volume using
whatever is in it" — forcing a flag reintroduces the manual hand-off
we want to remove.

### Option B — Direct function call from scanner to orchestrator

`scanner.scan_and_unlock(...)` that does both. Rejected because it
couples the two subsystems and makes the scanner depend on the
orchestrator (wrong direction — the scanner is a lower layer).

### Option C — Write keys to disk; orchestrator reads them on startup

Persists the pool across runs but leaks master keys to disk, which is
unacceptable. Rejected.

### Option D — Pass candidates through a dedicated queue, not the event bus

More efficient in principle, but fragments the observability story
(ADR 0008): dashboard panels and replay recorders watch the event
bus; a dedicated queue would be invisible to them. The extra
efficiency is not worth the visibility loss at current scales.

## References

- Source: `src/deepview/detection/` — the scanner.
- Source: `src/deepview/storage/containers/unlock.py` — module
  docstring names the `MasterKey` candidate path.
- Source: `src/deepview/core/events.py` — `EncryptionKeyFoundEvent`.
- Architecture page: [`../architecture/containers.md`](../architecture/containers.md)
- Guide: [`../guides/unlock-auto-with-memory-key.md`](../guides/unlock-luks-volume.md)
- Related ADR: [0005 — Pluggable unlocker](0005-pluggable-unlocker-via-module-attr.md)
- Related ADR: [0008 — Events over callbacks](0008-events-not-callbacks.md)
  — the wiring mechanism.
- Related ADR: [0004 — ProcessPool default](0004-process-pool-default-offload-backend.md)
  — what the orchestrator falls back to when no pooled key works.
