# Elastic / Elasticsearch

This guide streams Deep View detection events into Elasticsearch (or
Elastic Cloud) using the official [`elasticsearch-py`][espy] client and
[Elastic Common Schema (ECS)][ecs] field names. The forwarder is wired
the same way as the [Splunk HEC recipe](splunk.md) — it subscribes to
`EventClassifiedEvent`, `RootkitDetectedEvent`, and
`BaselineDeviationEvent` on the core `EventBus` — but serializes events
to ECS and uses the `_bulk` API.

[espy]: https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html
[ecs]: https://www.elastic.co/guide/en/ecs/current/index.html

See the [events reference][events] and
[tracing architecture][arch-trace] for the underlying types.

[events]: ../reference/events.md
[arch-trace]: ../architecture/tracing-and-classification.md

## Prerequisites

- Elasticsearch 8.x (self-hosted or Elastic Cloud).
- `pip install elasticsearch>=8.10.0`.
- An API key with `write` and `create_index` on `deepview-*` indices.
- Deep View editable install with the `tracing` extra.

## ECS mapping

Deep View events are rich native Python dataclasses. The forwarder maps
the most common fields to ECS so that downstream dashboards (SIEM app,
Discover) light up without custom field definitions.

| Deep View field | ECS field | Notes |
| --------------- | --------- | ----- |
| `event.event_id` | `event.id` | Stable UUIDv7. |
| `event.timestamp` | `@timestamp` | ISO-8601 UTC. |
| `event.pid` | `process.pid` | |
| `event.ppid` | `process.parent.pid` | |
| `event.process` | `process.name` | |
| `event.executable` | `process.executable` | Absolute path. |
| `event.uid` | `user.id` | String form. |
| `event.argv` | `process.args` | List, preserves order. |
| `event.rule_name` | `rule.name` | From classifier. |
| `event.classifications` | `event.category` | Multi-valued. |
| `event.severity` | `event.severity` | Numeric (1-10). |
| `event.host` | `host.name` | Defaults to `socket.gethostname()`. |
| `event.src_ip` / `event.dst_ip` | `source.ip` / `destination.ip` | For network events. |
| `event.indicator` | `threat.indicator.type` | Rootkit events. |
| `event.baseline` | `anomaly.baseline` | Non-ECS custom namespace. |

!!! info "Custom namespace"
    Deep View keeps anomaly-specific fields (`anomaly.baseline`,
    `anomaly.distance`, `anomaly.feature_name`) under a top-level
    `anomaly.*` namespace to avoid colliding with ECS promotions.

## Index template

Install this template once before indexing so mappings are correct:

```json
PUT _index_template/deepview
{
  "index_patterns": ["deepview-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "deepview-30d"
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "event": {
          "properties": {
            "id": {"type": "keyword"},
            "kind": {"type": "keyword"},
            "severity": {"type": "byte"},
            "category": {"type": "keyword"}
          }
        },
        "process": {
          "properties": {
            "pid": {"type": "long"},
            "name": {"type": "keyword"},
            "args": {"type": "keyword"},
            "executable": {"type": "keyword"}
          }
        },
        "rule": {"properties": {"name": {"type": "keyword"}}},
        "anomaly": {
          "properties": {
            "baseline": {"type": "float"},
            "distance": {"type": "float"},
            "feature_name": {"type": "keyword"}
          }
        }
      }
    }
  }
}
```

## Ingest pipeline

Use an ingest pipeline to enrich events with a `deepview.received_at`
timestamp, geo-resolve IPs, and lowercase rule names:

```json
PUT _ingest/pipeline/deepview-enrich
{
  "description": "Normalize Deep View events at ingest",
  "processors": [
    {"set": {"field": "deepview.received_at", "value": "{{_ingest.timestamp}}"}},
    {"lowercase": {"field": "rule.name", "ignore_missing": true}},
    {"geoip": {"field": "source.ip", "target_field": "source.geo", "ignore_missing": true}},
    {"geoip": {"field": "destination.ip", "target_field": "destination.geo", "ignore_missing": true}},
    {"remove": {"field": ["event.raw"], "ignore_missing": true}}
  ]
}
```

Point the index template at the pipeline by adding
`"index.default_pipeline": "deepview-enrich"` under `settings`.

## `elastic_forwarder.py`

```python
"""Bulk-index Deep View detection events into Elasticsearch."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_streaming_bulk

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    BaselineDeviationEvent,
    EventClassifiedEvent,
    RootkitDetectedEvent,
)
from deepview.tracing.manager import TraceManager

log = logging.getLogger("deepview.elastic")

_HOST = socket.gethostname()


def _to_ecs(event: Any) -> dict[str, Any]:
    """Flatten a Deep View event dataclass into ECS-style fields."""
    base = asdict(event) if hasattr(event, "__dataclass_fields__") else dict(vars(event))
    kind = type(event).__name__.removesuffix("Event")
    now = datetime.now(tz=timezone.utc).isoformat()
    doc: dict[str, Any] = {
        "@timestamp": base.get("timestamp", now),
        "event": {
            "id": base.get("event_id"),
            "kind": kind,
            "category": base.get("classifications", []),
            "severity": base.get("severity"),
        },
        "host": {"name": _HOST},
        "process": {
            "pid": base.get("pid"),
            "parent": {"pid": base.get("ppid")} if base.get("ppid") else None,
            "name": base.get("process"),
            "args": base.get("argv"),
            "executable": base.get("executable"),
        },
        "user": {"id": str(base["uid"])} if base.get("uid") is not None else None,
        "rule": {"name": base.get("rule_name")} if base.get("rule_name") else None,
    }
    if "src_ip" in base or "dst_ip" in base:
        doc["source"] = {"ip": base.get("src_ip")}
        doc["destination"] = {"ip": base.get("dst_ip")}
    if isinstance(event, BaselineDeviationEvent):
        doc["anomaly"] = {
            "baseline": base.get("baseline"),
            "distance": base.get("distance"),
            "feature_name": base.get("feature_name"),
        }
    if isinstance(event, RootkitDetectedEvent):
        doc.setdefault("threat", {})["indicator"] = {"type": base.get("indicator")}
    return _prune(doc)


def _prune(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _prune(v) for k, v in obj.items() if v not in (None, {}, [])}
    if isinstance(obj, list):
        return [_prune(v) for v in obj]
    return obj


class ElasticForwarder:
    def __init__(self, *, client: AsyncElasticsearch, index_prefix: str = "deepview") -> None:
        self._client = client
        self._prefix = index_prefix
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10_000)
        self._stopped = asyncio.Event()

    def enqueue(self, event: Any) -> None:
        doc = _to_ecs(event)
        doc["_index"] = f"{self._prefix}-{datetime.utcnow():%Y.%m.%d}"
        try:
            self._queue.put_nowait(doc)
        except asyncio.QueueFull:
            log.warning("elastic queue full, dropping %s", doc["event"]["kind"])

    async def _generator(self) -> Any:
        while not (self._stopped.is_set() and self._queue.empty()):
            doc = await self._queue.get()
            yield doc

    async def run(self) -> None:
        async for ok, info in async_streaming_bulk(
            client=self._client,
            actions=self._generator(),
            chunk_size=200,
            max_retries=3,
            initial_backoff=1,
            max_backoff=10,
        ):
            if not ok:
                log.error("bulk failure: %s", info)

    async def stop(self) -> None:
        self._stopped.set()


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    ctx = AnalysisContext.create()
    tm = TraceManager.from_context(ctx)

    client = AsyncElasticsearch(
        hosts=[os.environ["ELASTIC_URL"]],
        api_key=os.environ["ELASTIC_API_KEY"],
    )
    forwarder = ElasticForwarder(client=client)

    ctx.events.subscribe(EventClassifiedEvent, forwarder.enqueue)
    ctx.events.subscribe(RootkitDetectedEvent, forwarder.enqueue)
    ctx.events.subscribe(BaselineDeviationEvent, forwarder.enqueue)

    task = asyncio.create_task(forwarder.run())
    try:
        await tm.run_forever()
    finally:
        await forwarder.stop()
        await task
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Kibana tips

- Create a data view `deepview-*` with `@timestamp` as the time field.
- Promote `event.category` as the split-by for the SIEM app.
- Use Lens with `rule.name` → `event.severity` to build a detection
  heatmap.
- Combine with the `geoip` enrichment above to draw a world-map of
  suspicious source IPs.

!!! warning "Caveats"
    - **Bulk API throughput** is bounded by coordinating-node CPU and
      shard count. Deep View's internal fan-out drops events on queue
      overflow, so Elasticsearch backpressure does not stall the trace
      pipeline — but you will lose visibility. Monitor the drop counters
      on `TraceEventBus`.
    - **Schema drift.** ECS fields are not validated at index time
      unless you pin a strict mapping. Upgrade the index template in
      lockstep with Deep View minor versions.
    - **Retention cost.** A single sensor with a noisy classifier can
      push hundreds of MB/day. Use ILM with a hot → warm → delete policy
      keyed on `@timestamp`.
    - **API key scope.** Grant the forwarder only `write` and
      `auto_configure` on `deepview-*`; avoid cluster-wide privileges.
