# Wireshark / pcapng export

Deep View's network subsystem emits two typed events relevant to pcap
export:

- `NetworkPacketObservedEvent` — a packet seen by the live tracer or
  `inspect/NetInspector`, containing parsed headers plus the original
  bytes.
- `NetworkPacketMangledEvent` — a packet that passed through the
  `networking/MangleEngine`, with the original and post-mangle bytes
  plus the matched rule.

Both events can be serialized to a pcapng file that Wireshark (and
tshark) reads without plugins. This guide uses
[`scapy.utils.PcapNgWriter`][pcapng] because it supports per-packet
comments — we use those to annotate mangled packets with their rule
name.

[pcapng]: https://scapy.readthedocs.io/en/latest/api/scapy.utils.html#scapy.utils.PcapNgWriter

See the [events reference][events] and the
[tracing-and-classification architecture][arch-trace] doc for how the
events are produced.

[events]: ../reference/events.md
[arch-trace]: ../architecture/tracing-and-classification.md

## Prerequisites

- `pip install scapy` (optional dep; don't add it to core Deep View).
- Deep View installed with the `tracing` extra.
- Read access to the interface you want to capture (CAP_NET_RAW or
  root).

!!! note "Stdlib-only alternative"
    If you cannot add scapy, the Python stdlib `struct` module can
    synthesize a minimal pcap (not pcapng) file. See `networking/parser.py`
    for the header layouts — Deep View already parses the relevant
    fields.

## Recipe

```python
"""Mirror Deep View packet events to a pcapng file."""
from __future__ import annotations

import asyncio
import logging
import time

from scapy.utils import PcapNgWriter

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    NetworkPacketMangledEvent,
    NetworkPacketObservedEvent,
)
from deepview.tracing.manager import TraceManager

log = logging.getLogger("deepview.pcap")


class PcapMirror:
    def __init__(self, path: str) -> None:
        self._writer = PcapNgWriter(path, append=False, sync=False, linktype=1)
        self._writer.__enter__()
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        async with self._lock:
            self._writer.__exit__(None, None, None)

    def on_observed(self, event: NetworkPacketObservedEvent) -> None:
        self._emit(event.raw_bytes, ts=event.timestamp, comment=None)

    def on_mangled(self, event: NetworkPacketMangledEvent) -> None:
        comment_pre = f"deepview:rule={event.rule_name} phase=pre"
        comment_post = f"deepview:rule={event.rule_name} phase=post verdict={event.verdict}"
        self._emit(event.original_bytes, ts=event.timestamp, comment=comment_pre)
        if event.mangled_bytes and event.mangled_bytes != event.original_bytes:
            self._emit(event.mangled_bytes, ts=event.timestamp, comment=comment_post)

    def _emit(self, raw: bytes, *, ts: float, comment: str | None) -> None:
        from scapy.layers.l2 import Ether
        pkt = Ether(raw) if raw[:2] not in (b"\x45", b"\x46") else _fabricate_l2(raw)
        pkt.time = ts
        if comment:
            pkt.comment = comment.encode()
        self._writer.write(pkt)


def _fabricate_l2(raw: bytes) -> "Ether":
    """Some eBPF probes deliver L3-only bytes. Wrap in a synthetic Ethernet frame."""
    from scapy.layers.l2 import Ether
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x0800) / raw


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    ctx = AnalysisContext.create()
    tm = TraceManager.from_context(ctx)
    mirror = PcapMirror(f"deepview-{int(time.time())}.pcapng")

    ctx.events.subscribe(NetworkPacketObservedEvent, mirror.on_observed)
    ctx.events.subscribe(NetworkPacketMangledEvent, mirror.on_mangled)

    try:
        await tm.run_forever()
    finally:
        await mirror.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Analyzing in Wireshark

Open the resulting `.pcapng` and Wireshark will show a "Packet comments"
column you can enable via _View → Columns_. Filter on mangle rule hits:

```wireshark
pkt_comment contains "rule=slowloris_drop"
```

Or export only mangled packets to CSV via tshark:

```bash
tshark -r deepview-*.pcapng -Y 'pkt_comment contains "rule="' \
    -T fields -e frame.time_epoch -e pkt_comment -e ip.src -e ip.dst \
    -E separator=, > mangles.csv
```

## Correlating with classifier events

If you run the dashboard with `--enable-mangle`, both mangle events and
classifier events share an `event_id`. A simple join in Jupyter:

```python
import pandas as pd
classified = pd.read_json("classified.ndjson", lines=True)
mangled    = pd.read_json("mangled.ndjson", lines=True)
joined = classified.merge(mangled, on="event_id", suffixes=("_cls", "_pkt"))
```

lines up the rule trigger with the packet that caused it.

!!! warning "Caveats"
    - **File size.** pcapng with comments is roughly 1.5x the size of a
      vanilla pcap. For a busy mangle rule, rotate the output by time
      (hourly) or size (256 MiB) and archive offline.
    - **Link-type mismatch.** Deep View's eBPF probes sometimes deliver
      L3 bytes (IPv4/IPv6) without an Ethernet header. The helper
      `_fabricate_l2` synthesizes one; this is cosmetic only and should
      not be relied on for MAC-based filtering downstream.
    - **Privacy.** A pcap mirror contains full payload bytes. Encrypt
      the destination volume and rotate aggressively if the sensor sees
      production traffic — Deep View does not redact cleartext
      credentials captured in packet payloads.
    - **Wireshark versions** below 3.0 may not render per-packet
      comments; use Wireshark 4.x for best results.
