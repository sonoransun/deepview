# Events Reference

Every event class lives in `src/deepview/core/events.py`. The `EventBus`
is a synchronous pub/sub with a parallel async fan-out for `async`
handlers; the tracing subsystem additionally layers an async
`TraceEventBus` on top (see `tracing/stream.py`).

Events are published via `context.events.publish(ev)` (sync) or
`await context.events.publish_async(ev)` (sync handlers run first, then
async ones). Handlers may subscribe to either the exact subclass or any
parent — the bus walks `isinstance` relationships.

This page enumerates **every concrete event class** in `core/events.py`,
grouped by domain. Every class is a plain-Python class (not a dataclass);
construct with keyword arguments as shown.

## Summary

| Class | Fields | Published by | Subscribed by |
|-------|--------|--------------|---------------|
| `Event` | – | Base class; never published directly | – |
| `MemoryAcquiredEvent` | `path`, `dump_format`, `size_bytes` | `memory/acquisition/*` after a successful dump | Report engine, artifact store |
| `SuspiciousPatternEvent` | `offset`, `rule_name`, `data` | YARA scanner in `scanning/yara.py` | Classifier, report engine |
| `ProcessDetectedEvent` | `pid`, `ppid`, `comm`, `timestamp` | Memory analysis (`pslist`, `linux_proc`) | Classifier, timeline |
| `RootkitDetectedEvent` | `technique`, `description`, `severity`, `evidence` | `detection/anti_forensics.py`, DKOM detector | Alert monitor, report engine |
| `ArtifactRecoveredEvent` | `artifact_type`, `source`, `count`, `metadata` | Any plugin publishing artifact extraction success | Artifact store, timeline |
| `MemoryDiffEvent` | `changed_pages`, `new_pages`, `removed_pages`, `change_rate` | `memory/diff/*` differential analysis | Report engine, dashboard |
| `BaselineDeviationEvent` | `category`, `description`, `severity`, `evidence` | `detection/anomaly.py` | Alert monitor, classifier |
| `NetworkPacketObservedEvent` | `ts_ns`, `direction`, `ip_version`, `src`, `dst`, `proto`, `sport`, `dport`, `length` | `networking/engine.py` on every packet seen | Flow-rate and top-talkers dashboard panels |
| `NetworkPacketMangledEvent` | `ts_ns`, `rule_id`, `action`, `verdict`, `direction`, `description`, `remote`, `pid_guess`, `comm_guess`, `before_bytes`, `after_bytes` | `MangleEngine` on every matched mangle action | `ManglePanel` in `cli/dashboard/panels.py`, session store |
| `EventClassifiedEvent` | `source_event`, `rule_id`, `severity`, `labels`, `attack_ids`, `title` | `classification/classifier.py` | `monitor alert`, dashboard alerts panel |
| `ContainerUnlockStartedEvent` | `format`, `layer`, `key_source` | `UnlockOrchestrator` before every attempt | Dashboard progress, replay store |
| `ContainerUnlockProgressEvent` | `format`, `stage`, `attempted`, `total` | `Passphrase.derive()` via `OffloadEngine` | Dashboard progress |
| `ContainerUnlockedEvent` | `format`, `layer`, `produced_layer`, `elapsed_s` | `UnlockOrchestrator._try_sources()` on success | Timeline, report engine |
| `ContainerUnlockFailedEvent` | `format`, `layer`, `reason` | `UnlockOrchestrator.auto_unlock()` when every candidate exhausted | Alert monitor |
| `RemoteAcquisitionStartedEvent` | `endpoint`, `transport`, `output` | `memory/acquisition/remote/factory.py` | Dashboard remote panel |
| `RemoteAcquisitionProgressEvent` | `endpoint`, `bytes_done`, `bytes_total`, `stage` | `RemoteAcquisitionProvider._emit_progress()` | Dashboard, CLI progress |
| `RemoteAcquisitionCompletedEvent` | `endpoint`, `output`, `size_bytes`, `elapsed_s` | Remote provider on clean exit | Timeline, report engine |
| `OffloadJobSubmittedEvent` | `job_id`, `kind`, `backend`, `cost_hint` | `OffloadEngine.submit()` | Dashboard offload counter |
| `OffloadJobProgressEvent` | `job_id`, `fraction`, `message` | GPU backends and long-running process jobs | Dashboard progress bar |
| `OffloadJobCompletedEvent` | `job_id`, `ok`, `elapsed_s`, `backend`, `error` | `OffloadEngine` on future completion | Timeline, report engine |

## Memory and process events

### `MemoryAcquiredEvent`

Emitted after a successful memory capture.

```python
class MemoryAcquiredEvent(Event):
    def __init__(self, path, dump_format, size_bytes=0): ...
```

Example handler:

```python
from deepview.core.events import MemoryAcquiredEvent

def on_acquired(ev: MemoryAcquiredEvent) -> None:
    print(f"captured {ev.size_bytes} bytes to {ev.path} ({ev.dump_format})")

ctx.events.subscribe(MemoryAcquiredEvent, on_acquired)
```

### `ProcessDetectedEvent`

One event per unique process surfaced by memory analysis or `/proc` walking.
Carries `pid`, `ppid`, `comm`, and an optional `timestamp` (float seconds).

### `MemoryDiffEvent`

Differential analysis output: `changed_pages` / `new_pages` /
`removed_pages` are integers, `change_rate` is a ratio between 0 and 1.

### `SuspiciousPatternEvent`

Published by YARA / IoC scanners. `offset` is the absolute byte offset within
the scanned layer. `data` is a short context buffer.

## Detection / classification events

### `RootkitDetectedEvent`

Severity defaults to `"critical"`. `evidence` is a free-form dict — DKOM
detectors set it to the cross-reference result, page-hiding detectors set
it to the kernel-object address.

### `BaselineDeviationEvent`

Anomaly detection output, severity defaults to `"warning"`.

### `EventClassifiedEvent`

Published by `classification/classifier.py` when a live `MonitorEvent` matches
a YAML rule. `source_event` is the original trace event, `rule_id` is the
matched rule id, `severity` is the rule's severity (`info`/`warning`/
`critical`), `labels` is a free-form `dict[str, str]`, `attack_ids` is a list
of MITRE ATT&CK technique ids, and `title` is the rule's human-readable
title.

```python
from deepview.core.events import EventClassifiedEvent

def on_classified(ev: EventClassifiedEvent) -> None:
    if ev.severity == "critical":
        print(f"!! {ev.rule_id}: {ev.title}")

ctx.events.subscribe(EventClassifiedEvent, on_classified)
```

### `ArtifactRecoveredEvent`

Generic "we just carved something useful" signal. Plugins set
`artifact_type` to a short tag (`"browser_history"`, `"registry_key"`,
`"shellbag"`, ...) and `source` to the layer name / process id.

## Network events

### `NetworkPacketObservedEvent`

Fires for every packet the mangle engine sees, *before* ruleset evaluation.
Useful for flow-rate accounting. Fields: `ts_ns`, `direction` (`"in"` /
`"out"`), `ip_version` (4 or 6), `src`, `dst`, `proto` (`"tcp"`, `"udp"`,
`"icmp"`, `"other"`), `sport`, `dport`, `length`.

### `NetworkPacketMangledEvent`

Fires for every matched mangle action. Critical for downstream
visibility — the dashboard's `ManglePanel` drives its counters, top-rules
view, and recent-actions table off this event.

```python
class NetworkPacketMangledEvent(Event):
    def __init__(self, *, ts_ns, rule_id, action, verdict, direction,
                 description="", remote="", pid_guess=0, comm_guess="",
                 before_bytes=0, after_bytes=0): ...
```

Example:

```python
from deepview.core.events import NetworkPacketMangledEvent

def on_mangle(ev: NetworkPacketMangledEvent) -> None:
    if ev.verdict == "drop":
        print(f"DROPPED by {ev.rule_id}: {ev.remote}")

ctx.events.subscribe(NetworkPacketMangledEvent, on_mangle)
```

## Container unlock events

All four are published by `UnlockOrchestrator` and the per-adapter
`Unlocker.unlock()` implementations in
`storage/containers/*`.

### `ContainerUnlockStartedEvent`

One event per `(format, layer, key_source)` tuple before each attempt. Fields:
`format` (`"luks"`, `"veracrypt"`, `"bitlocker"`, `"filevault2"`), `layer`
(source layer's metadata name), `key_source` (`"master_key"`, `"keyfile"`,
`"passphrase"`).

### `ContainerUnlockProgressEvent`

Periodic progress during a multi-step unlock, primarily KDF iterations.
Fields: `format`, `stage` (`"kdf"`, `"trial_decrypt"`, `"header_scan"`),
`attempted`, `total`.

### `ContainerUnlockedEvent`

Success. `produced_layer` is the registered name of the resulting
`DecryptedVolumeLayer`; `elapsed_s` is monotonic seconds from attempt start.

### `ContainerUnlockFailedEvent`

All candidate sources exhausted. `reason` is a short string (e.g. `"all
candidate keys exhausted"`).

```python
from deepview.core.events import (
    ContainerUnlockStartedEvent,
    ContainerUnlockedEvent,
    ContainerUnlockFailedEvent,
)

def report(ev) -> None:
    if isinstance(ev, ContainerUnlockedEvent):
        print(f"{ev.format}: unlocked in {ev.elapsed_s:.2f}s as {ev.produced_layer}")
    elif isinstance(ev, ContainerUnlockFailedEvent):
        print(f"{ev.format}: failed ({ev.reason})")

for cls in (ContainerUnlockStartedEvent, ContainerUnlockedEvent, ContainerUnlockFailedEvent):
    ctx.events.subscribe(cls, report)
```

## Remote acquisition events

All three come from providers under `memory/acquisition/remote/`.

### `RemoteAcquisitionStartedEvent`

Fields: `endpoint` (host), `transport` (`"ssh-dd"`, `"tcp-stream"`,
`"network-agent"`, `"dma-pcie"`, ...), `output` (local output path).

### `RemoteAcquisitionProgressEvent`

Published by `RemoteAcquisitionProvider._emit_progress(bytes_done,
bytes_total, stage)`. Fields: `endpoint`, `bytes_done`, `bytes_total`,
`stage`.

### `RemoteAcquisitionCompletedEvent`

Success. Fields: `endpoint`, `output`, `size_bytes`, `elapsed_s`.

```python
from deepview.core.events import RemoteAcquisitionProgressEvent

def show(ev: RemoteAcquisitionProgressEvent) -> None:
    pct = (ev.bytes_done / ev.bytes_total * 100) if ev.bytes_total else 0
    print(f"{ev.endpoint} {ev.stage}: {pct:.1f}%")

ctx.events.subscribe(RemoteAcquisitionProgressEvent, show)
```

## Offload events

Published by `offload/engine.py::OffloadEngine.submit()` and backend-specific
progress callbacks.

### `OffloadJobSubmittedEvent`

Fields: `job_id` (UUID hex), `kind` (`"pbkdf2_sha256"`, `"argon2id"`,
`"sha512"`, ...), `backend` (`"thread"`, `"process"`, `"gpu-opencl"`,
`"gpu-cuda"`, `"remote"`), `cost_hint` (integer heuristic, higher = heavier).

### `OffloadJobProgressEvent`

Fields: `job_id`, `fraction` (0.0–1.0), `message` (optional). GPU backends
emit progress approximately once per kernel launch; process-pool backends
emit once at job start and once at completion.

### `OffloadJobCompletedEvent`

Fields: `job_id`, `ok`, `elapsed_s`, `backend`, `error` (`None` if `ok`).

```python
from deepview.core.events import OffloadJobCompletedEvent

def benchmark(ev: OffloadJobCompletedEvent) -> None:
    if not ev.ok:
        print(f"[offload] {ev.job_id} FAILED on {ev.backend}: {ev.error}")

ctx.events.subscribe(OffloadJobCompletedEvent, benchmark)
```

## Subscribing to parents

The bus walks `isinstance` against every registered type — subscribing to
`Event` gets you every event class:

```python
from deepview.core.events import Event

def log_everything(ev: Event) -> None:
    print(type(ev).__name__, vars(ev))

ctx.events.subscribe(Event, log_everything)
```

This is how the `replay.recorder.SessionRecorder` captures every event into a
single SQLite row stream without enumerating each subclass.

## Async handlers

Use `subscribe_async` to register a coroutine handler. Sync handlers run
first during `publish_async`; async ones are awaited sequentially after.

```python
import asyncio

async def a_handler(ev):
    await asyncio.sleep(0)  # yield
    print("async saw", type(ev).__name__)

ctx.events.subscribe_async(EventClassifiedEvent, a_handler)
await ctx.events.publish_async(classified_event)
```

## Cross-references

- ABCs that generate each event: [interfaces.md](interfaces.md).
- CLI commands that wire subscribers: [cli.md](cli.md).
- Classification ruleset format (produces `EventClassifiedEvent`):
  see `src/deepview/classification/builtin_rules/`.
