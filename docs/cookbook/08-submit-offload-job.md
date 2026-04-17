# Recipe 08: Submit an offload job

Send a CPU-bound computation to the offload engine and await the result,
observing the events it publishes onto the bus.

!!! note "Extras required"
    None — `ThreadPoolBackend` and `ProcessPoolBackend` are stdlib-only
    and always registered. Add `[offload_gpu]` for `gpu-opencl` /
    `gpu-cuda` backends.

## The recipe

```python
from deepview.core.context import AnalysisContext
from deepview.core.events import OffloadJobCompletedEvent, OffloadJobSubmittedEvent
from deepview.offload.jobs import make_job

ctx = AnalysisContext()

# --- 1. Subscribe to the bus so we see what happens -------------------
def on_submit(evt: OffloadJobSubmittedEvent) -> None:
    print(f"submitted job_id={evt.job_id} kind={evt.kind} backend={evt.backend}")

def on_done(evt: OffloadJobCompletedEvent) -> None:
    print(f"done      job_id={evt.job_id} ok={evt.ok} elapsed={evt.elapsed_s:.3f}s")

ctx.events.subscribe(OffloadJobSubmittedEvent, on_submit)
ctx.events.subscribe(OffloadJobCompletedEvent, on_done)

# --- 2. Build + submit a job ------------------------------------------
# The built-in KDF handlers accept a dict payload; for custom work use
# callable_ref="mymodule:myfunc" — the worker resolves it via importlib.
job = make_job(
    kind="pbkdf2_sha256",
    payload={
        "password": "hunter2",
        "salt": b"\x00" * 16,
        "iterations": 100_000,
        "dklen": 32,
    },
    callable_ref="deepview.offload.kdf:pbkdf2_sha256",
)
future = ctx.offload.submit(job)           # default backend: "process"

# --- 3. Await + inspect ------------------------------------------------
result = future.await_result(timeout=30.0)
print("ok =", result.ok, "backend =", result.backend)
print("hex =", result.output.hex() if result.ok else None)
```

## What happened

1. `context.offload` lazily constructs an `OffloadEngine` on first
   access. At construction it registers `thread` + `process` backends
   unconditionally and `gpu-opencl` / `gpu-cuda` only if their
   `is_available()` probes succeed.
2. `engine.submit(job)` publishes an `OffloadJobSubmittedEvent` onto
   `context.events`, hands the job to the selected backend's
   `concurrent.futures.Executor`, and wraps the underlying future in an
   `OffloadFuture`. When the future resolves, the engine publishes an
   `OffloadJobCompletedEvent`.
3. `future.await_result(timeout=...)` is a thin wrapper around
   `Future.result` that normalises exceptions into an `OffloadResult`
   with `ok=False` rather than raising.

!!! tip "Pick the right backend"
    ```python
    ctx.offload.submit(job, backend="thread")      # I/O-heavy or non-picklable
    ctx.offload.submit(job, backend="gpu-opencl")  # OpenCL-capable workloads
    ctx.offload.submit(job, backend="gpu-cuda")    # CUDA-capable workloads
    ctx.offload.submit(job, backend="remote")      # gRPC to a worker pool
    ```
    The default is `process`, chosen because every built-in KDF workload
    is CPU-bound and process-parallelism bypasses the GIL cleanly.

!!! warning "Pickling"
    `process` and `remote` backends pickle the payload. Avoid lambdas
    and bound methods; use `callable_ref="module:function"` and a
    plain-data payload (dicts / lists / bytes / ints / strings).

## Cross-links

- Architecture: [`architecture/offload.md`](../architecture/offload.md).
- [Recipe 05](05-unlock-luks-with-passphrase.md) — LUKS unlock dispatches
  its PBKDF2 through this exact engine.
- Events: [`reference/events.md`](../reference/events.md).
