# 0008. Typed events through the EventBus, not per-call callbacks

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Deep View has many producers of runtime activity — trace providers,
acquisition engines, offload jobs, unlock attempts, scanner hits,
packet-mangling verdicts — and many consumers — the CLI renderer, the
rich dashboard, the session recorder, the classification engine, the
replay engine. Any pair might need to connect.

Two common patterns for this wiring:

1. **Callbacks passed at call time.** `engine.submit(job,
   on_progress=..., on_complete=...)`. The producer calls the
   callbacks directly.
2. **Typed events through a bus.** The producer constructs an
   `OffloadJobSubmittedEvent(...)` and publishes it onto
   `context.events`; subscribers register handlers by event *type*.

The project has both patterns used at different points in its
history, and we wanted a single answer.

## Decision

**Typed `Event` classes published through `AnalysisContext.events`
(`EventBus`) are the canonical way to communicate runtime activity.**
Per-call callbacks are discouraged; explicit `on_xxx=` parameters
should be removed on the next touch unless there is a compelling
locality reason to keep them (rare).

Specifically:

- Every subsystem that wants to emit activity defines a dataclass in
  `deepview.core.events` subclassing the base `Event`.
- Events are **immutable frozen dataclasses**. A consumer cannot
  mutate history.
- Subscribers register with `context.events.subscribe(EventType,
  handler)`. Handlers receive the exact type or any subclass thereof
  (parent-class subscription).
- Async handlers use `publish_async`; the tracing subsystem layers a
  `TraceEventBus` on top with per-subscriber bounded queues that drop
  on overflow rather than apply backpressure.
- Every event is picklable (so it survives the session recorder's
  SQLite round-trip in the replay subsystem).

## Consequences

### Positive

- **Uniform observability.** A single subscriber on
  `context.events.subscribe(Event, recorder.on_event)` captures
  *everything* for replay. Adding a new event type requires no change
  to the recorder.
- **Multiple consumers, one producer.** The dashboard, the CLI
  renderer, the session recorder, and the classification engine all
  subscribe to the same offload event stream without any of them
  being visible to each other or to the producer.
- **Replay is free.** Events are the natural record format. The
  replay engine re-publishes them onto a private bus and any
  event-driven consumer behaves identically.
- **Decoupling.** The offload engine does not need to know that a
  dashboard exists; the dashboard does not need to know that the
  offload engine's module exists. Both refer to
  `OffloadJobCompletedEvent` and nothing else.
- **Type-safe.** Each event is a typed dataclass with named fields;
  mypy catches shape mismatches at the subscribe site.
- **Natural audit trail.** Dual-use operations (remote acquisition,
  network mangling, container unlocks) emit events containing their
  authorization banner and their verdict, so reports have a complete
  log without any extra plumbing.

### Negative

- **Indirection.** A one-off "run a function and tell me when it's
  done" caller has to read the event types to learn what gets
  published. We mitigate with a reference page (`docs/reference/events.md`)
  that lists every event class and its fields.
- **No back-pressure.** The core `EventBus` fans out synchronously
  in-order; the `TraceEventBus` async variant drops on overflow. A
  slow consumer cannot throttle a producer. This is intentional — we
  do not want a debug dashboard to jam a live-monitoring session —
  but it means high-fidelity event capture requires the session
  recorder (which writes batches to SQLite, not the main bus).
- **Overhead per event.** Constructing and dispatching a dataclass
  per event is more work than calling a bare callback. Measured
  overhead for the current shapes is low (< 1µs per dispatch with a
  handful of subscribers), but for hot paths (eBPF fan-out,
  per-packet mangling) we profile carefully and use bulk-publish or
  summary events where appropriate.

### Neutral

- Existing callback parameters remain on a few APIs (notably
  acquisition providers whose `progress_callback` predates the event
  bus). We mark them deprecated and route them through the bus
  internally; direct callers still work, new callers should subscribe.

## Alternatives considered

### Option A — Callbacks everywhere

`engine.submit(job, on_progress=..., on_complete=...)`. Rejected:

- Every producer grows a combinatorial set of callback parameters.
- Multiple consumers require the producer to invent a list-of-callbacks
  parameter, which is exactly an event bus in disguise.
- Typing gets awkward (callback signatures are hard to express
  precisely in `Callable[..., ...]`).

### Option B — Signals / weak-refs (Blinker, PyDispatcher)

Uses string signal names as the subscription key. Rejected because
string names are not type-checked; a typo in a subscriber goes
silent until the producer emits a signal that nobody hears.

### Option C — asyncio.Queue per producer

Each producer exposes a queue; consumers read from it. Rejected:

- Couples consumers to the specific producer.
- Forces consumers to choose asyncio even when they don't need to.
- Replay requires a separate recording mechanism per queue.

### Option D — Untyped dict events

Publish `{"type": "offload.submitted", "job_id": ...}` dicts. Rejected
because it abandons type-checking at the bus boundary. The MADR cost
is not worth avoiding a few dataclass definitions.

## References

- Source: `src/deepview/core/events.py` — every event class.
- Source: `src/deepview/core/context.py` — `EventBus` implementation.
- Source: `src/deepview/tracing/stream.py` — `TraceEventBus` async
  variant with overflow drop semantics.
- Reference page: [`../reference/events.md`](../reference/events.md)
- Related ADR: [0004 — ProcessPool default](0004-process-pool-default-offload-backend.md)
  — uses events for job lifecycle.
- Related ADR: [0006 — Fail-secure remote acquisition](0006-fail-secure-remote-acquisition.md)
  — uses events for the signed banner.
- Related ADR: [0007 — EncryptionKeyScanner feeds unlocker](0007-encryptionkeyscanner-feeds-unlocker.md)
  — uses events for cross-subsystem wiring.
