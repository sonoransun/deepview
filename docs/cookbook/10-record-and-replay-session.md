# Recipe 10: Record and replay a session

Persist trace events into a SQLite session file, then replay them later
into a private `TraceEventBus`. The replayer's invariant is that the
replayed events are indistinguishable from live ones to any downstream
classifier or renderer.

!!! note "Extras required"
    Stdlib only (sqlite3 is in the stdlib; the schema uses the `json1`
    extension bundled with modern Python builds). Add
    `[linux_monitoring]` to actually have a live tracer to record from.

## The recipe — record

```python
import asyncio
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.replay import SessionRecorder, SessionStore
from deepview.tracing.manager import TraceManager

async def record(session_path: Path) -> str:
    ctx = AnalysisContext()
    tracer = TraceManager.from_context(ctx)
    await tracer.start()

    store = SessionStore(session_path)
    recorder = SessionRecorder(tracer.bus, store)
    session_id = await recorder.start()

    try:
        await asyncio.sleep(30)            # capture 30 seconds
    finally:
        await recorder.stop()
        await tracer.stop()
        store.close()

    return session_id

session_path = Path("/tmp/today.dvsession")
session_id = asyncio.run(record(session_path))
print(f"recorded session={session_id!r} at {session_path}")
```

## The recipe — replay

```python
import asyncio
from pathlib import Path

from deepview.classification.classifier import EventClassifier
from deepview.classification.ruleset import Ruleset
from deepview.core.context import AnalysisContext
from deepview.replay import SessionReader, SessionReplayer

async def replay(session_path: Path, session_id: str) -> None:
    ctx = AnalysisContext()
    reader = SessionReader(session_path)
    replayer = SessionReplayer(reader, session_id, speed=4.0)

    # Classifier consumes the replayer's private bus exactly like live.
    classifier = EventClassifier(
        bus=replayer.bus,
        core_bus=ctx.events,
        ruleset=Ruleset.load_builtin(),
    )
    await classifier.start()

    stats = await replayer.play()
    print(f"replayed {stats.events_published}/{stats.events_read} events")
    await classifier.stop()

asyncio.run(replay(session_path, session_id))
```

## What happened

- `SessionStore` opens a SQLite database with `PRAGMA journal_mode=WAL`
  and batches inserts up to 1000 events per flush. One database can
  hold multiple sessions; each has a `uuid.uuid4().hex[:12]` ID and a
  captured `capabilities` dict (hostname, kernel, filter text).
- `SessionRecorder` subscribes to the tracer's `TraceEventBus` and
  writes every event it receives. It respects the bus's per-subscriber
  drop policy: recording saturation increments `dropped_count` rather
  than blocking the tracer.
- `SessionReplayer.play()` walks the stored events in timestamp order
  and republishes them to a *private* `TraceEventBus`. `speed=4.0`
  means events are compressed to 1/4 their original wall time;
  `speed=0` or `step=True` disables pacing entirely.

!!! tip "Replay through a different ruleset"
    Point the classifier at `Ruleset.load_from(Path("custom.yaml"))`
    while replaying the same session to re-detect against new rules
    without re-acquiring data.

!!! warning "Schema compatibility"
    Sessions are written by one Deep View version; the replayer
    tolerates older schemas via column-lookup fallbacks, but crossing a
    major version bump is not guaranteed. Pin the Deep View version
    alongside the evidence.

## Equivalent CLI

```bash
deepview monitor --record /tmp/today.dvsession --duration 30s
deepview replay /tmp/today.dvsession --speed 4x
```

## Cross-links

- [Recipe 09](09-stream-trace-events.md) — consume the events live.
- Architecture: [`architecture/tracing-and-classification.md`](../architecture/tracing-and-classification.md).
- Storage: schema DDL in
  [`replay/schema.py`](https://github.com/your-org/deepseek/blob/main/src/deepview/replay/schema.py).
