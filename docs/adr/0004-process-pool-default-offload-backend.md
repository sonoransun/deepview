# 0004. ProcessPool is the default offload backend

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

The offload engine (`src/deepview/offload/engine.py`) dispatches expensive
computations off the caller thread. Its four in-tree backends are
`ThreadPoolBackend`, `ProcessPoolBackend`, `OpenCLBackend`, and
`CUDABackend` (GPU backends register only if their probe succeeds).

Every backend speaks the same `OffloadBackend` ABC; the engine picks a
backend per-job by name or falls back to a default. The question is
what that default should be.

The dominant workload category today is **password-based key derivation**:
PBKDF2-SHA256/SHA512 and Argon2id, driven by the container-unlock
orchestrator. These workloads are:

- **CPU-bound.** Each iteration is a tight SHA / memory-hard loop.
- **Long-lived.** KDF attempts at realistic iteration counts run for
  hundreds of milliseconds to tens of seconds.
- **Pickle-friendly.** Inputs are `(passphrase: bytes, salt: bytes,
  iterations: int, dk_len: int)` — all picklable.
- **Expected in aggregate.** An auto-unlock against a wordlist dispatches
  thousands of jobs.

Python's GIL serialises pure-Python CPU work across threads in a single
interpreter. Even when `hashlib.pbkdf2_hmac` releases the GIL internally,
contention around the interpreter lock still caps thread-pool parallelism
well below core count.

## Decision

**The default backend is `"process"` (`ProcessPoolBackend`).** Callers who
have I/O-bound or not-picklable work pass `backend="thread"` explicitly.
GPU backends are selected with `backend="opencl"` or `backend="cuda"`.

`context.offload.submit(job)` without a `backend=` argument goes through
the process pool.

## Consequences

### Positive

- **Real multicore scaling for KDF work.** PBKDF2 / Argon2id attempts
  scale nearly linearly with `cpu_count` instead of being throttled by
  the GIL.
- **Crash isolation.** A segfault in a native crypto extension kills a
  worker process, not the whole `deepview` invocation. The engine's
  future raises a clean exception that the orchestrator catches.
- **Deterministic warm-up.** `ProcessPoolBackend` eagerly spawns workers
  in `__init__`, so the first submit doesn't pay fork/spawn cost.
- **Aligns with the most common workload.** The unlock orchestrator is
  the heaviest user of the engine; it benefits immediately.

### Negative

- **Pickle boundary.** Jobs must be picklable; closures over local
  lambdas or file handles don't work. We document this in the offload
  guide and the backend ABC docstring.
- **Higher memory footprint.** Every worker is a full interpreter. On a
  16-core machine this is ~100 MB of overhead; for the workloads we
  care about it's negligible relative to data already held.
- **Slower round-trip for trivial jobs.** Submitting a 10 µs callable
  through a process pool incurs pickle + IPC overhead in the
  hundreds-of-microseconds range. Callers for whom that matters use
  `backend="thread"`.
- **Fork-unfriendly environments.** On macOS the `spawn` start method
  is mandatory and re-imports; any side-effect-heavy module imported
  in the child pays that cost. We keep `__main__`-guarded scripts and
  the lazy-import rule (ADR 0002) to limit the damage.

### Neutral

- The choice is an engine default, not a hard-coded behaviour. Every
  call site can override — this ADR documents the default, not the
  contract.

## Alternatives considered

### Option A — Thread pool default

Keeps everything in one interpreter, no pickle boundary, cheapest
possible submit. Rejected because the dominant workload is CPU-bound
and would see almost no parallelism. Threads remain the right choice
for I/O-heavy jobs — they're still selectable, just not the default.

### Option B — GPU default when available

Probe for CUDA/OpenCL at engine construction and default to whichever
is present. Rejected because:

- GPU suitability is workload-dependent. A 10-iteration SHA1 is faster
  on CPU than on GPU because of kernel-launch overhead.
- Probe-succeeds is not the same as probe-is-healthy; a driver
  mismatch or out-of-memory situation is a runtime failure.
- We want GPU to be an explicit opt-in so users understand the cost
  and driver requirements.

We do provide a `submit_auto(job)` helper that heuristically picks GPU
for large Argon2id jobs and CPU for small PBKDF2 jobs, but it is not the
engine's default.

### Option C — Dispatch based on job-type annotation

Jobs could carry a `preferred_backend` attribute and the engine would
honour it. We did implement this as a hint but not as a default —
jobs without an explicit preference still go through the documented
default. Keeping the default visible and configurable is simpler.

### Option D — Remote backend default

`RemoteBackend` (for a future gRPC worker pool) would enable cluster
scaling. Rejected: no cluster exists until a remote worker is deployed,
so "default on" would fail on first submit for 99% of users.

## References

- Source: `src/deepview/offload/engine.py` (module docstring explicitly
  states "Default backend is `process`...").
- Source: `src/deepview/offload/backends/process.py`
- Source: `src/deepview/offload/backends/thread.py`
- Source: `src/deepview/storage/containers/unlock.py` — the heaviest
  offload consumer.
- Architecture page: [`../architecture/offload.md`](../architecture/offload.md)
- Related ADR: [0008 — Events over callbacks](0008-events-not-callbacks.md)
  — the engine publishes `OffloadJobSubmittedEvent` /
  `OffloadJobCompletedEvent` through the same bus.
