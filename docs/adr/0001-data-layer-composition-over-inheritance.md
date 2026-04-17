# 0001. Data-layer composition over inheritance

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Deep View inherits its storage primitive — the `DataLayer` — from the
Volatility 3 project. A `DataLayer` is a byte-addressed source exposing
`read(offset, length) -> bytes`, `write(...)` (optional), `is_valid`, and
`scan(...)`. Every concrete layer wraps one or more *backing* layers and
transforms reads on the way through.

The storage subsystem (added in v0.2) stacks several such layers on top
of one another for a single forensic image:

```
RawNANDLayer                # the mmap'd image bytes
  └─ ECCDataLayer           # BCH / Hamming / Reed-Solomon correction
       └─ LinearizedFlashLayer  # FTL (LBA -> physical page mapping)
            └─ PartitionLayer       # GPT / MBR slice
                 └─ DecryptedVolumeLayer  # LUKS / BitLocker / VeraCrypt
                      └─ Filesystem adapter
```

We had to decide whether to model these transformations as a class
hierarchy (each stage subclasses the previous) or as independent
classes that *hold a reference* to their backing layer.

The same question applies to cross-cutting concerns: a cache layer, a
read-only guard layer, a snapshot layer. These should compose freely
with any of the above without inheriting from any one of them.

## Decision

**Every storage transformation is a standalone class that takes its
backing `DataLayer` as a constructor argument.** There is no inheritance
relationship between `ECCDataLayer`, `LinearizedFlashLayer`,
`PartitionLayer`, or `DecryptedVolumeLayer`. Each one implements the
`DataLayer` interface directly (via ABC) and delegates to its inner
layer through an attribute.

Concretely: `ECCDataLayer(backing: DataLayer, decoder: ECCDecoder,
geometry: NANDGeometry)` returns something that is itself a `DataLayer`,
with no knowledge of what `backing` actually is or does.

## Consequences

### Positive

- **Arbitrary stacking.** A user can point an `ECCDataLayer` at a file,
  at another `ECCDataLayer`, at a remote network layer, at a
  `SnapshotLayer`, or at a test-only in-memory fake. The composition is
  fully open.
- **Trivial unit tests.** Every layer's tests construct a
  `BytesIOLayer` backing, wrap it, and assert on reads. No mock
  hierarchy needed.
- **Clean separation of concerns.** ECC code lives with ECC code; FTL
  code lives with FTL code. Neither knows about the other.
- **Natural home for decorators.** A `ReadOnlyLayer(inner)` or
  `CachingLayer(inner, size=...)` drops in anywhere in the stack.
- **Matches Volatility 3's original design**, which we rely on heavily.

### Negative

- **Slightly more boilerplate per layer.** Each class must forward
  `is_valid` / `scan` / size reporting to its backing, even when it has
  no transformation to apply for those methods. We tolerate it.
- **No shared state via `self`.** Layers that need shared context
  (e.g., the NAND geometry across an ECC layer and the FTL above it)
  must pass it explicitly. This is the right trade-off but costs a few
  extra constructor arguments.

### Neutral

- The architecture encourages a proliferation of small classes. We
  think the clarity is worth it; the "too many classes" objection is
  usually a request for inheritance in disguise.

## Alternatives considered

### Option A — Deep inheritance chain

`ECCDataLayer(DataLayer)`, then `FTLLayer(ECCDataLayer)`, then
`PartitionLayer(FTLLayer)`, and so on. Rejected because:

- Hard-codes a single canonical stack. A raw-image user with no ECC
  would have to skip a class level.
- Subclasses couple tightly to superclass internals, making it hard to
  evolve any one layer without breaking the chain.
- Does not match real workflow: a LUKS container on top of a plain
  partition table has no ECC or FTL in the stack at all.

### Option B — Middleware / pipeline pattern

A single `LayerPipeline` that owns a list of `Transform` callables and
applies them in order. Rejected because:

- Transforms are not all pure functions of bytes → bytes. FTL needs
  the `NANDGeometry`; partition layers need the partition entry they
  describe; ECC decoders maintain decoder state. A callable signature
  would have to grow to carry all of it.
- Loses the "each layer is itself a `DataLayer`" property, which is
  what lets scanners, YARA runners, and file-system adapters bind to
  any level of the stack uniformly.

### Option C — Mixin classes for cross-cutting concerns

Separate `ReadOnlyMixin`, `CachingMixin`, etc. Rejected because mixins
and multiple inheritance interact badly with Python's MRO when the base
class hierarchy itself is non-trivial, and we already rejected the
hierarchy in Option A.

## References

- Source: `src/deepview/interfaces/layer.py` (the `DataLayer` ABC)
- Source: `src/deepview/storage/` — concrete layers
- Architecture page: [`../architecture/storage.md`](../architecture/storage.md)
- External: Volatility 3 `framework/interfaces/layers.py` — the
  ancestor design we are extending.
- Related ADR: [0008 — Events over callbacks](0008-events-not-callbacks.md),
  which ensures observability doesn't force inheritance either.
