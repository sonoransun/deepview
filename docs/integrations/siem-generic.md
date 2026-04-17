# Generic SIEM (JSON lines over stdout)

For SIEMs and log pipelines that do not have a first-party Deep View
recipe (Graylog, Chronicle, Sumo Logic, Datadog, Loki, Sentinel, …) the
universal integration is to emit newline-delimited JSON on stdout and
let the operator's existing agent (fluentd, vector.dev, Filebeat,
rsyslog-omfwd, …) pick it up.

This guide documents the on-the-wire format and a drop-in subscriber
module.

See [reference/events][events] for the event schema.

[events]: ../reference/events.md

## Wire format

One JSON object per line, UTF-8, no trailing commas, `@timestamp` in
ISO-8601 UTC:

```json
{"@timestamp":"2026-04-14T09:12:15.120Z","kind":"event_classified","host":"sensor-01","event_id":"c2f9...","pid":4711,"process":"bash","rule_name":"suspicious_shell_child","severity":7,"classifications":["execution.shell"]}
```

The envelope is intentionally flat so downstream parsers do not have to
unwind nested objects. Non-scalar fields (argv, metadata) are kept as
JSON sub-objects.

## Subscriber

```python
"""Stream Deep View events as newline-delimited JSON on stdout."""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import socket
import sys
from datetime import datetime, timezone
from typing import Any

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    BaselineDeviationEvent,
    EventClassifiedEvent,
    RootkitDetectedEvent,
    NetworkPacketMangledEvent,
)
from deepview.tracing.manager import TraceManager

log = logging.getLogger("deepview.siem")
HOST = socket.gethostname()


def to_line(event: Any) -> str:
    kind = {
        EventClassifiedEvent: "event_classified",
        RootkitDetectedEvent: "rootkit_detected",
        BaselineDeviationEvent: "baseline_deviation",
        NetworkPacketMangledEvent: "packet_mangled",
    }.get(type(event), type(event).__name__)
    payload = (
        dataclasses.asdict(event)
        if dataclasses.is_dataclass(event)
        else dict(vars(event))
    )
    payload.setdefault(
        "@timestamp",
        datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    payload["kind"] = kind
    payload["host"] = HOST
    return json.dumps(payload, default=str, separators=(",", ":"))


def write(event: Any) -> None:
    try:
        sys.stdout.write(to_line(event) + "\n")
        sys.stdout.flush()
    except Exception:
        log.exception("stdout write failed")


async def main() -> None:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    ctx = AnalysisContext.create()
    tm = TraceManager.from_context(ctx)
    for cls in (
        EventClassifiedEvent,
        RootkitDetectedEvent,
        BaselineDeviationEvent,
        NetworkPacketMangledEvent,
    ):
        ctx.events.subscribe(cls, write)
    await tm.run_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

## Collector snippets

=== "fluentd"

    ```conf
    <source>
      @type exec
      tag deepview
      command /opt/deepview/venv/bin/python /opt/deepview/siem.py
      format json
      run_interval 0
    </source>
    ```

=== "vector.dev"

    ```toml
    [sources.deepview]
    type = "exec"
    command = ["/opt/deepview/venv/bin/python", "/opt/deepview/siem.py"]
    decoding.codec = "json"
    streaming.respawn_on_exit = true
    ```

=== "rsyslog"

    ```conf
    module(load="omfwd")
    input(type="imfile" File="/var/log/deepview/events.jsonl"
          Tag="deepview:" ruleset="to-siem")
    ```

## Failure modes

- **Broken pipe** — if the consumer dies, `sys.stdout.write` raises
  `BrokenPipeError`. The subscriber logs and continues; Deep View's
  event bus keeps publishing.
- **Backpressure** — stdout is line-buffered and flushing on every line
  is slow on high-throughput probes. For sustained high event rates,
  write to a rotating log file via `logging.handlers.RotatingFileHandler`
  and point the collector at the file.

!!! warning "Caveats"
    - **Rate limits.** stdout is synchronous; on a busy sensor emitting
      thousands of events per second, the flush can starve the trace
      loop. Prefer file-based buffering for > 500 events/sec and let
      vector / fluentd tail the file.
    - **Schema drift.** The `kind` field is stable; all other fields
      follow the Deep View event dataclass — treat as semi-stable.
      Version your SIEM parsers to the Deep View minor version.
    - **Retention cost.** JSON lines compress well (6-10x with zstd).
      Apply compression before long-term archival.
    - **PII hygiene.** `metadata.argv` and `url` can contain secrets,
      tokens, or user data. Apply SIEM-side redaction rules before
      feeding downstream analytics.
