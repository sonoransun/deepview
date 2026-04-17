# Offload Throughput

This page explains how to pick a backend for
[`OffloadEngine.submit`](../architecture/offload.md), and what performance
ceiling each one actually hits in practice.

!!! warning "Synthetic numbers"
    Every figure in this document comes from the built-in
    `deepview offload benchmark` command on a single 16-core x86 workstation.
    Treat them as order-of-magnitude, not as an SLA. Run the benchmark on
    your own box before making capacity decisions.

## Backends at a glance

Deep View ships four backends. Two always register (they are stdlib-only);
the GPU backends register only if their probe succeeds:

| Backend | Always available | Typical use | Notes |
|---|---|---|---|
| `thread` | Yes | I/O-heavy or GIL-releasing native code | No pickle cost; shares interpreter |
| `process` | Yes | **Default.** CPU-bound KDFs, SHA-512 loops | Escapes the GIL; pickle cost per job |
| `gpu-opencl` | If `pyopencl` + ICD present | PBKDF2 / SHA-512 batches | Falls back to CPU on any kernel error |
| `gpu-cuda` | If `pycuda` + NVCC present | PBKDF2 / SHA-512 batches on NVIDIA | Same fallback contract as OpenCL |

The engine's constructor registers both CPU backends unconditionally and
probes the GPU ones via `is_available()` before registering them, so
`engine.status()` on a core install honestly reports exactly what works.

## Why ProcessPool is the default

Every built-in KDF in Deep View is CPU-bound:

- `pbkdf2_sha256` — tight loop of HMAC rounds, bottlenecked by SHA-256.
- `argon2id` — memory-hard, but still CPU-bound at the `argon2-cffi` layer.
- `sha512_iter` — repeated `hashlib.sha512` updates.

`hashlib` releases the GIL inside its C implementation, so in principle you
could run these on threads. In practice, Argon2id's memory churn plus the
Python dispatch overhead in `deepview.offload.kdf` means the GIL contention
shows up. ProcessPool side-steps the question entirely — each worker is a
separate interpreter — and scales near-linearly with core count.

!!! note "Why the default is `process`, not `thread`"
    The engine literally hard-codes this:

    ```python
    OffloadEngine(context, default_backend="process")
    ```

    Callers pass `backend="thread"` explicitly for I/O work or when the
    payload is not picklable.

## Thread vs. Process

| Criterion | `thread` | `process` |
|---|---|---|
| GIL escape | Only if the callee releases it | Always |
| Pickle cost | **None** | ~10–50 µs per small payload |
| Payload size ceiling | RAM | ~50 MiB practical (pickle + IPC copy) |
| Startup cost | ~0 | `os.cpu_count()` fork on engine construction |
| Works with un-picklable callables | **Yes** | No — raises at submit |
| In-flight accounting | Per-backend lock | Per-backend lock |

Typical numbers for the empty-payload dispatch path (submit → done):

| Backend | Sustained jobs/s (warm) | Bottleneck |
|---|---|---|
| `thread` | ~100 000 | Queue lock contention |
| `process` | ~10 000 | Pickle + IPC |

!!! tip "Batching is the only way to outrun pickle"
    The engine exposes `submit_many(jobs, *, backend=...)` which yields
    results in completion order. If you have 10 000 candidate passphrases,
    submitting them individually spends ~1 s just on pickle; packing them
    into one job with a `list[bytes]` payload reduces that to a single
    round-trip.

## GPU: when it wins and when it loses

Both `gpu-opencl` and `gpu-cuda` implement two kernels:

- `pbkdf2_sha256` — one work-item per `(password, salt)` pair.
- `sha512_iter` — repeated SHA-512 of a buffer for N rounds (VeraCrypt / TrueCrypt).

And explicitly **refuse** `argon2id` (more on that below).

### PBKDF2: batch size is everything

Kernel launch + host↔device copy overhead is ~200 µs on a consumer card.
The CPU PBKDF2 path does 100 000 iterations at SHA-256 in roughly 300 ms on
one core. So the break-even point is:

```
batch_size  ≈  kernel_launch_cost / per_password_cpu_cost
            ≈  200 µs  /  0.0003 µs (per iteration / work-item)
            ≈  O(thousands)
```

Measured on the reference box, with 100 000 PBKDF2-SHA-256 iterations:

| Batch size | `process` (8 cores) | `gpu-cuda` | Speedup |
|---|---|---|---|
| 1 | 0.3 s | 0.28 s | ~1.1× (noise) |
| 100 | 3.8 s | 0.32 s | ~12× |
| 1 000 | 38 s | 0.9 s | ~42× |
| 10 000 | 380 s | 4.2 s | ~90× |

!!! tip "Rule of thumb"
    - **Single-passphrase unlock**: use `process`. GPU overhead dominates.
    - **Dictionary attack on memory-dumped LUKS** (≥ 1 000 candidates):
      use `gpu-cuda` or `gpu-opencl`. Fall back to `process` if probe
      fails — the engine does this automatically via the `[cpu-fallback]`
      suffix on `OffloadResult.backend`.

### Argon2id on GPU: intentionally stubbed

The GPU backends honestly refuse Argon2id:

- The kernel raises `NotImplementedError` with a message pointing at the
  CPU `argon2-cffi` path.
- Argon2id's defining property is that it is **memory-hard**. At realistic
  parameters (64 MiB per derivation × hundreds of threads in flight) you'd
  need tens to hundreds of GB of VRAM.
- Consumer GPUs max out at 24 GB; datacentre cards at 80 GB. Neither is
  enough to GPU-accelerate Argon2id meaningfully, which is precisely why
  Argon2 was chosen by the PHC for password hashing.

!!! warning "This is a feature, not a gap"
    If you need to brute-force an Argon2id-protected LUKS2 container, the
    answer is to either reduce the candidate space (dictionary, rules) or
    accept CPU-bound throughput. There is no GPU shortcut — by design.

## Benchmark methodology

The CLI ships a built-in benchmark command that exercises every registered
backend with the same job shape:

```bash
deepview offload benchmark --kind=pbkdf2_sha256 --iterations=32
deepview offload benchmark --kind=argon2id --iterations=8
deepview offload benchmark --kind=sha512 --iterations=64
```

What it does:

1. Builds a synthetic payload appropriate for `--kind`.
2. Submits `--iterations` copies of the job to the named backend (or the
   default if `--backend` is omitted).
3. Waits for every future; reports wall-clock elapsed, mean per-job
   `elapsed_s` from `OffloadResult.elapsed_s`, and observed throughput.
4. Emits `OffloadJobSubmittedEvent` / `OffloadJobCompletedEvent` into the
   core event bus — the dashboard picks these up.

!!! tip "Reproducing these numbers"
    ```bash
    # warm the process pool (fork on first submit)
    deepview offload benchmark --kind=pbkdf2_sha256 --iterations=1

    # real run
    deepview offload benchmark --kind=pbkdf2_sha256 --iterations=32 --backend=process

    # compare to GPU if available
    deepview offload benchmark --kind=pbkdf2_sha256 --iterations=32 --backend=gpu-cuda
    ```

## Sample numbers

Reference box: 16-core Ryzen 9 7950X, 64 GiB DDR5, RTX 4070 Ti, Python 3.12.

| Workload | Backend | Wall-clock for 32 jobs | Jobs/s | Per-job |
|---|---|---|---|---|
| PBKDF2-SHA-256 (100 000 iter, `dklen=32`) | `process` | 1.2 s | ~27 | ~37 ms |
| PBKDF2-SHA-256 (100 000 iter, `dklen=32`) | `gpu-cuda` | 0.3 s | ~107 | kernel-amortized |
| Argon2id (64 MiB / 3 / 4) | `process` | 2.1 s | ~15 | ~66 ms |
| SHA-512 × 500 000 | `process` | 0.9 s | ~36 | ~28 ms |
| Empty payload (dispatch only) | `thread` | 0.00032 s | ~100 000 | — |
| Empty payload (dispatch only) | `process` | 0.0032 s | ~10 000 | — |

!!! warning "Again: synthetic"
    These figures were captured once on one box. Use
    `deepview offload benchmark` on your hardware.

## Events and observability

Every offload submission publishes two events on the core `EventBus`:

- `OffloadJobSubmittedEvent` — synchronous, before the work is scheduled.
- `OffloadJobCompletedEvent` — from a stdlib-future `done_callback`, always
  fires as long as `submit()` returned a future (submit-time exceptions
  bubble directly and produce no future).

The `OffloadResult.elapsed_s` field is the authoritative timing source —
it's measured with `time.perf_counter()` inside the worker, so it excludes
submit-side queueing but includes pickle overhead for the process backend.

## Related reading

- [Offload architecture](../architecture/offload.md) — dispatch model,
  registration order, event contract.
- [Unlock cookbook: PBKDF2](../cookbook/offload-pbkdf2.md) — concrete end-to-end
  example of batching a dictionary attack.
- [Memory overhead](memory-overhead.md) — why ProcessPool's RSS footprint
  grows with worker count.
- [Profiling](profiling.md) — how to measure the above yourself.
