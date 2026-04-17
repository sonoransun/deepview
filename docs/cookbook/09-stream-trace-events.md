# Recipe 09: Stream trace events

Subscribe to classified trace events on the core `EventBus` and print
incoming detections as they arrive. This is what `deepview monitor`
builds its renderer on top of.

!!! note "Extras required"
    `pip install -e ".[linux_monitoring]"` for the eBPF tracer on Linux.
    Classification itself is stdlib-only.

## The recipe

```python
import asyncio

from deepview.core.context import AnalysisContext
from deepview.classification.events import EventClassifiedEvent
from deepview.classification.classifier import EventClassifier
from deepview.classification.ruleset import Ruleset
from deepview.tracing.manager import TraceManager

async def main() -> None:
    ctx = AnalysisContext()

    # --- 1. Build a tracer from the context ---------------------------
    tracer = TraceManager.from_context(ctx)
    await tracer.start()

    # --- 2. Attach a classifier with the built-in ruleset ------------
    rules = Ruleset.load_builtin()
    classifier = EventClassifier(
        bus=tracer.bus,            # private async TraceEventBus
        core_bus=ctx.events,       # shared sync EventBus
        ruleset=rules,
    )
    await classifier.start()

    # --- 3. Subscribe to classified events on the core bus ----------
    def on_hit(evt: EventClassifiedEvent) -> None:
        tags = ",".join(evt.classifications)
        print(f"[{evt.severity}] {tags} -> "
              f"{evt.event.comm}({evt.event.pid}) {evt.event.summary()}")

    ctx.events.subscribe(EventClassifiedEvent, on_hit)

    # --- 4. Run for a while -----------------------------------------
    try:
        await asyncio.sleep(60)
    finally:
        await classifier.stop()
        await tracer.stop()

asyncio.run(main())
```

## What happened

There are *two* buses in play:

- `TraceEventBus` — async, bounded, drops on overflow. Owned by the
  tracer; consumed by the classifier, recorder, and live renderer.
- Core `EventBus` (`context.events`) — sync, topic-style. Receives
  `EventClassifiedEvent`s from the classifier so panels, reports, and
  this recipe can handle them without talking to the tracer directly.

The classifier is the bridge: it dequeues `MonitorEvent`s from the
trace bus, runs each through its `Ruleset`, mutates
`MonitorEvent.metadata["classifications"]`, and publishes an
`EventClassifiedEvent` onto the core bus. That decouples everything
downstream of classification from the tracer's async machinery.

!!! tip "Filter inside the subscriber"
    The event includes `evt.severity` (`"info"` / `"warning"` /
    `"critical"`) and `evt.classifications` (tag list). Filter on these
    rather than rebuilding the ruleset.

!!! warning "Dropping events"
    The async bus drops events when any subscriber's queue fills (see
    `CLAUDE.md` contract: trace queues do not apply backpressure). If
    you see gaps, narrow the filter at the probe rather than the
    handler.

## Equivalent CLI

```bash
deepview monitor --filter 'comm="curl"' --ruleset builtin
```

## Cross-links

- Architecture: [`architecture/tracing-and-classification.md`](../architecture/tracing-and-classification.md).
- [Recipe 10](10-record-and-replay-session.md) — persist these events
  for offline replay.
- Events: [`reference/events.md`](../reference/events.md).
