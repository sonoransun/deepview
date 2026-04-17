# Splunk HTTP Event Collector

This guide forwards Deep View detection events into Splunk via the
[HTTP Event Collector (HEC)][splunk-hec]. The recipe subscribes to three
event classes on the core [`EventBus`][arch-context]:

- `EventClassifiedEvent` — fired when the classifier matches a rule
  against a `MonitorEvent`.
- `RootkitDetectedEvent` — emitted by `detection/anti_forensics.py` when
  a kernel rootkit indicator is observed.
- `BaselineDeviationEvent` — emitted by `detection/anomaly.py` when a
  process's feature vector exceeds the learned baseline.

See the [events reference][events] for the full schema of each class.

[splunk-hec]: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
[arch-context]: ../architecture/tracing-and-classification.md
[events]: ../reference/events.md

## Prerequisites

1. A Splunk instance (Cloud or Enterprise ≥ 8.2) with HEC enabled.
2. A HEC token with `main` or a dedicated index assigned.
3. Deep View installed with `pip install -e ".[dev,tracing]"`.
4. Python `requests` or `httpx` — the example uses `httpx` for async.

!!! note "Index hygiene"
    We recommend a dedicated index such as `deepview` with a 90-day
    retention and a sourcetype like `deepview:classified` so that
    Splunk's field extraction rules do not collide with your other log
    sources.

## Wire format

Each Deep View event is serialized into a Splunk HEC envelope:

```json
{
  "time": 1734200000.123,
  "host": "sensor-01",
  "source": "deepview",
  "sourcetype": "deepview:classified",
  "index": "deepview",
  "event": {
    "kind": "event_classified",
    "event_id": "c2f9...a3",
    "pid": 4711,
    "process": "bash",
    "rule_name": "suspicious_shell_child",
    "severity": "high",
    "classifications": ["execution.shell", "persistence"],
    "metadata": { "cwd": "/tmp", "argv": ["bash", "-c", "curl ..."] }
  }
}
```

The `event.kind` field lets Splunk searches discriminate between the
three sub-streams without relying on distinct sourcetypes:

```spl
index=deepview event.kind="rootkit_detected"
```

## `splunk_forwarder.py`

Save this as `splunk_forwarder.py` in your Deep View working tree. It
builds an `AnalysisContext`, attaches to the event bus, and ships every
matching event to HEC with a bounded retry loop.

```python
"""Forward Deep View detection events to Splunk HEC."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from dataclasses import asdict
from typing import Any

import httpx

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    BaselineDeviationEvent,
    EventClassifiedEvent,
    RootkitDetectedEvent,
)
from deepview.tracing.manager import TraceManager

log = logging.getLogger("deepview.splunk")


class SplunkForwarder:
    """Batch Deep View events and POST them to Splunk HEC."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        index: str = "deepview",
        source: str = "deepview",
        host: str | None = None,
        batch_size: int = 50,
        flush_interval: float = 2.0,
        verify_tls: bool = True,
    ) -> None:
        self.url = url.rstrip("/") + "/services/collector/event"
        self.headers = {"Authorization": f"Splunk {token}"}
        self.index = index
        self.source = source
        self.host = host or socket.gethostname()
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.verify_tls = verify_tls
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10_000)
        self._client: httpx.AsyncClient | None = None
        self._stopped = asyncio.Event()

    async def start(self) -> None:
        self._client = httpx.AsyncClient(
            headers=self.headers,
            verify=self.verify_tls,
            timeout=httpx.Timeout(10.0, connect=5.0),
        )

    async def stop(self) -> None:
        self._stopped.set()
        await self._flush()
        if self._client:
            await self._client.aclose()

    def enqueue(self, event: Any) -> None:
        envelope = self._wrap(event)
        try:
            self._queue.put_nowait(envelope)
        except asyncio.QueueFull:
            log.warning("splunk queue full, dropping %s", envelope["event"]["kind"])

    def _wrap(self, event: Any) -> dict[str, Any]:
        kind = {
            EventClassifiedEvent: "event_classified",
            RootkitDetectedEvent: "rootkit_detected",
            BaselineDeviationEvent: "baseline_deviation",
        }[type(event)]
        payload = asdict(event) if hasattr(event, "__dataclass_fields__") else dict(vars(event))
        payload["kind"] = kind
        return {
            "time": time.time(),
            "host": self.host,
            "source": self.source,
            "sourcetype": f"deepview:{kind}",
            "index": self.index,
            "event": payload,
        }

    async def run(self) -> None:
        """Drain the queue, flushing every `flush_interval` seconds."""
        while not self._stopped.is_set():
            await asyncio.sleep(self.flush_interval)
            await self._flush()

    async def _flush(self) -> None:
        if not self._client or self._queue.empty():
            return
        batch: list[dict[str, Any]] = []
        while not self._queue.empty() and len(batch) < self.batch_size:
            batch.append(self._queue.get_nowait())
        if not batch:
            return
        body = "\n".join(_json_dumps(b) for b in batch)
        for attempt in range(3):
            try:
                resp = await self._client.post(self.url, content=body)
                resp.raise_for_status()
                return
            except httpx.HTTPError as exc:
                log.warning("HEC post failed (attempt %d): %s", attempt + 1, exc)
                await asyncio.sleep(1.5 ** attempt)
        log.error("dropping %d events after 3 failed HEC attempts", len(batch))


def _json_dumps(obj: dict[str, Any]) -> str:
    import json
    return json.dumps(obj, default=str)


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    ctx = AnalysisContext.create()
    tm = TraceManager.from_context(ctx)

    forwarder = SplunkForwarder(
        url=os.environ["SPLUNK_HEC_URL"],
        token=os.environ["SPLUNK_HEC_TOKEN"],
        index=os.environ.get("SPLUNK_HEC_INDEX", "deepview"),
    )
    await forwarder.start()

    ctx.events.subscribe(EventClassifiedEvent, forwarder.enqueue)
    ctx.events.subscribe(RootkitDetectedEvent, forwarder.enqueue)
    ctx.events.subscribe(BaselineDeviationEvent, forwarder.enqueue)

    flusher = asyncio.create_task(forwarder.run())
    try:
        await tm.run_forever()
    finally:
        flusher.cancel()
        await forwarder.stop()


if __name__ == "__main__":
    asyncio.run(main())
```

## Running the forwarder

=== "Systemd"

    ```ini
    [Unit]
    Description=Deep View Splunk Forwarder
    After=network-online.target

    [Service]
    Environment=SPLUNK_HEC_URL=https://splunk.example.com:8088
    EnvironmentFile=/etc/deepview/splunk.env
    ExecStart=/opt/deepview/venv/bin/python /opt/deepview/splunk_forwarder.py
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
    ```

=== "Docker"

    ```dockerfile
    FROM python:3.12-slim
    RUN pip install deepview[tracing] httpx
    COPY splunk_forwarder.py /app/
    ENV SPLUNK_HEC_URL=https://splunk.example.com:8088
    ENTRYPOINT ["python", "/app/splunk_forwarder.py"]
    ```

=== "Ad hoc"

    ```bash
    export SPLUNK_HEC_URL=https://splunk.example.com:8088
    export SPLUNK_HEC_TOKEN=...  # HEC token
    python splunk_forwarder.py
    ```

## Splunk search examples

```spl
# High-severity classifications in the last hour
index=deepview event.kind="event_classified" event.severity="high"
| stats count by event.rule_name, event.process

# Processes triggering multiple baseline deviations
index=deepview event.kind="baseline_deviation"
| stats dc(event.event_id) as hits by event.pid, event.process
| where hits > 3

# Rootkit-adjacent hosts in the last 24h
index=deepview event.kind="rootkit_detected" earliest=-24h
| stats values(event.indicator) as indicators by host
```

## Dashboard

A starter dashboard XML is available in the Deep View wiki. It pivots on
`event.rule_name` and layers a timechart of `event.severity` counts to
surface bursts of high-severity detections.

!!! warning "Caveats"
    - **HEC rate limits.** Splunk Cloud caps HEC throughput per token;
      dedicated instances default to a few MB/s. Monitor the `batch_size`
      and `flush_interval` so the forwarder queue never saturates — once
      it fills, Deep View drops events silently rather than applying
      backpressure to the trace fan-out.
    - **Schema drift.** If you upgrade Deep View across a minor version,
      re-run Splunk's field discovery; new optional fields may appear on
      the `event` object.
    - **Retention cost.** A busy sensor can emit tens of thousands of
      `event_classified` records per hour. Tune the retention on the
      `deepview` index and keep raw `MonitorEvent` traffic on a separate
      tier or local `replay/` SQLite store.
    - **TLS verification.** `verify_tls=False` should only be used in
      lab setups. Production HEC endpoints must use a trusted CA chain.
