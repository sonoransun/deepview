# MISP

[MISP][misp] is a threat-sharing platform built around typed attributes
and events. Deep View's `IoCEngine` (under `src/deepview/scanning/`)
produces the raw material — hashes, domains, IPs, URLs, mutex names —
that maps cleanly onto MISP attribute types.

[misp]: https://www.misp-project.org/

This guide uses [PyMISP][pymisp] to push detections from a running Deep
View session into a MISP event. See
[reference/events][events] and
[interfaces][iface] for the underlying types.

[pymisp]: https://github.com/MISP/PyMISP
[events]: ../reference/events.md
[iface]: ../reference/interfaces.md

## Attribute mapping

`IoCEngine` findings (class `IoCFinding`) have:

```python
@dataclass(slots=True)
class IoCFinding:
    kind: str           # "sha256" | "md5" | "domain" | "ipv4" | "url" | "mutex" | "filename" | "yara"
    value: str
    confidence: float   # 0.0..1.0
    source: str         # plugin / rule name
    metadata: dict[str, Any]
```

The MISP attribute mapping:

| Deep View `kind` | MISP `type` | MISP `category` |
| ---------------- | ----------- | --------------- |
| `sha256` | `sha256` | `Payload delivery` |
| `md5` | `md5` | `Payload delivery` |
| `sha1` | `sha1` | `Payload delivery` |
| `domain` | `domain` | `Network activity` |
| `ipv4` | `ip-dst` | `Network activity` |
| `ipv6` | `ip-dst` | `Network activity` |
| `url` | `url` | `Network activity` |
| `mutex` | `mutex` | `Artifacts dropped` |
| `filename` | `filename` | `Artifacts dropped` |
| `yara` | `yara` | `External analysis` |
| `imphash` | `imphash` | `Payload delivery` |
| `ssdeep` | `ssdeep` | `Payload delivery` |

`confidence` maps onto MISP's `to_ids` flag (threshold at 0.7 by
default) and tags of the form `confidence:0.85`.

## `misp_publisher.py`

```python
"""Publish Deep View IoCFinding objects to MISP."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Iterable

from pymisp import MISPAttribute, MISPEvent, MISPTag, PyMISP

from deepview.scanning.ioc import IoCFinding

log = logging.getLogger("deepview.misp")

ATTR_MAP = {
    "sha256":  ("sha256",    "Payload delivery"),
    "md5":     ("md5",       "Payload delivery"),
    "sha1":    ("sha1",      "Payload delivery"),
    "domain":  ("domain",    "Network activity"),
    "ipv4":    ("ip-dst",    "Network activity"),
    "ipv6":    ("ip-dst",    "Network activity"),
    "url":     ("url",       "Network activity"),
    "mutex":   ("mutex",     "Artifacts dropped"),
    "filename":("filename",  "Artifacts dropped"),
    "yara":    ("yara",      "External analysis"),
    "imphash": ("imphash",   "Payload delivery"),
    "ssdeep":  ("ssdeep",    "Payload delivery"),
}


@dataclass(slots=True)
class MispConfig:
    url: str
    key: str
    verify_tls: bool = True
    tlp: str = "tlp:amber"
    min_confidence: float = 0.6
    to_ids_threshold: float = 0.7


class MispPublisher:
    def __init__(self, config: MispConfig) -> None:
        self._cfg = config
        self._client = PyMISP(config.url, config.key, ssl=config.verify_tls)

    def publish(
        self,
        findings: Iterable[IoCFinding],
        *,
        info: str,
        distribution: int = 0,
        threat_level_id: int = 3,
        analysis: int = 1,
    ) -> dict:
        event = MISPEvent()
        event.info = info
        event.distribution = distribution
        event.threat_level_id = threat_level_id
        event.analysis = analysis

        tlp = MISPTag()
        tlp.name = self._cfg.tlp
        event.add_tag(tlp)

        added = 0
        for f in findings:
            if f.confidence < self._cfg.min_confidence:
                continue
            try:
                mtype, category = ATTR_MAP[f.kind]
            except KeyError:
                log.debug("unmapped IoC kind: %s", f.kind)
                continue
            attr = MISPAttribute()
            attr.type = mtype
            attr.category = category
            attr.value = f.value
            attr.to_ids = f.confidence >= self._cfg.to_ids_threshold
            attr.comment = f"{f.source}: confidence={f.confidence:.2f}"
            attr.add_tag(f"deepview:source=\"{f.source}\"")
            attr.add_tag(f"confidence:{round(f.confidence, 2)}")
            event.add_attribute(**attr.to_dict())
            added += 1
        if added == 0:
            log.info("no IoCs above confidence threshold; skipping push")
            return {}
        return self._client.add_event(event, pythonify=True).to_dict()
```

## Example run

```python
from deepview.core.context import AnalysisContext
from deepview.scanning.ioc import IoCEngine
from misp_publisher import MispConfig, MispPublisher

ctx = AnalysisContext.create()
engine = IoCEngine(ctx)
findings = list(engine.scan(layer="primary"))

pub = MispPublisher(MispConfig(
    url=os.environ["MISP_URL"],
    key=os.environ["MISP_KEY"],
))
result = pub.publish(findings, info="Deep View scan: host=sensor-01 2026-04-14")
print("uploaded event:", result.get("Event", {}).get("id"))
```

## Consuming MISP back into Deep View

The reverse direction — pulling MISP feeds into a Deep View scanner —
is covered by `scanning/IoCEngine.load_misp_feed()`. Configure via
`deepview config edit` under `scanning.ioc.misp_feeds`.

!!! warning "Caveats"
    - **Rate limits.** MISP's `add_event` is not cheap; batch findings
      per scan rather than per-event. For streaming dedup, create a
      single MISP event per session and append attributes instead.
    - **Retention cost.** MISP grows quickly if you push raw
      `MonitorEvent`-derived IoCs. Apply a confidence floor (≥ 0.7 for
      `to_ids`) and de-dupe values client-side.
    - **Schema drift.** PyMISP tracks MISP server versions loosely —
      pin your PyMISP to within a minor version of the server or
      attribute addition may silently drop fields.
    - **Sharing distribution.** `distribution=0` ("your organization
      only") is the safe default. Promote to `1` (community) or higher
      only after analyst review. Never push a TLP:RED finding with
      `distribution >= 2`.
