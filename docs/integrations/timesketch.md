# Timesketch

[Timesketch][ts] is a collaborative forensic timeline analysis tool. It
accepts CSV, JSONL, and Plaso (`.plaso`) uploads. The simplest Deep
View → Timesketch handoff is to export the `filesystem_timeline` plugin
output (or any `PluginResult` with timestamps) as a Timesketch CSV.

[ts]: https://timesketch.org/

See [reference/plugins][plugins] and
[tracing-and-classification][arch-trace] for background.

[plugins]: ../reference/plugins.md
[arch-trace]: ../architecture/tracing-and-classification.md

## Timesketch CSV schema

Timesketch expects at minimum:

| Column | Description |
| ------ | ----------- |
| `datetime` | ISO-8601 UTC timestamp. |
| `timestamp_desc` | Free-text description of what the time represents (e.g., "Modification time"). |
| `message` | Human-readable one-liner shown in the timeline UI. |

Optional columns are surfaced as tags / attributes in the UI.

## Field mapping

The `filesystem_timeline` plugin emits the following columns:

| Deep View column | Timesketch column | Notes |
| ---------------- | ----------------- | ----- |
| `timestamp` | `datetime` | Cast to `isoformat()`. |
| `macb` | `timestamp_desc` | e.g., `M`, `A`, `C`, `B` → expanded to `mtime` / `atime` / `ctime` / `btime`. |
| `path` | `message` | Prefixed with the MACB code for readability. |
| `inode` | `inode` | Optional attribute. |
| `uid` / `gid` | `uid` / `gid` | Numeric owner/group. |
| `size` | `file_size` | Bytes. |
| `mode` | `file_mode` | Octal string. |
| `volume` | `source_short` | For multi-volume sketches. |
| — | `data_type` | Hardcoded to `"fs:stat"` so Timesketch rules fire. |
| — | `source` | Hardcoded to `"Deep View"`. |

## `to_timesketch.py`

```python
"""Convert a Deep View PluginResult into a Timesketch-ready CSV."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Mapping

from deepview.interfaces.plugin import PluginResult


MACB_EXPAND = {"M": "Modification time", "A": "Access time",
               "C": "Change time", "B": "Birth time"}

TS_COLUMNS = [
    "datetime", "timestamp_desc", "message", "source", "source_short",
    "data_type", "inode", "uid", "gid", "file_size", "file_mode",
]


def rows_to_dicts(result: PluginResult) -> Iterable[Mapping[str, object]]:
    cols = result.columns
    for row in result.rows:
        rec = dict(zip(cols, row))
        yield rec


def to_timesketch(result: PluginResult, output: str | Path) -> Path:
    path = Path(output)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=TS_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for rec in rows_to_dicts(result):
            macb = str(rec.get("macb") or "")
            writer.writerow({
                "datetime": rec["timestamp"].isoformat() + "Z",
                "timestamp_desc": MACB_EXPAND.get(macb, macb or "Unknown"),
                "message": f"[{macb}] {rec.get('path', '')}",
                "source": "Deep View",
                "source_short": str(rec.get("volume") or "DV"),
                "data_type": "fs:stat",
                "inode": rec.get("inode"),
                "uid": rec.get("uid"),
                "gid": rec.get("gid"),
                "file_size": rec.get("size"),
                "file_mode": rec.get("mode"),
            })
    return path
```

## End-to-end example

```python
from deepview.core.context import AnalysisContext
from deepview.plugins.builtin.filesystem_timeline import FilesystemTimelinePlugin
from to_timesketch import to_timesketch

ctx = AnalysisContext.create()
plugin = FilesystemTimelinePlugin(ctx, volume="/evidence/disk.raw")
result = plugin.run()
to_timesketch(result, "disk-timeline.csv")
```

## Uploading

=== "Web UI"

    1. Create a new sketch.
    2. _Add timeline → Upload CSV/JSONL/Plaso_.
    3. Select `disk-timeline.csv` and give it a name.

=== "CLI"

    ```bash
    timesketch_importer \
        --host https://ts.example.com \
        --username analyst \
        --sketch_id 12 \
        --timeline_name deepview-disk-fs \
        disk-timeline.csv
    ```

=== "API"

    ```python
    from timesketch_api_client import client
    c = client.TimesketchApi("https://ts.example.com", "analyst", pw)
    sk = c.get_sketch(12)
    sk.upload("deepview-disk-fs", "disk-timeline.csv")
    ```

## Analyst workflow

Once imported, the timeline shows up alongside other sources. Useful
starting filters:

- `tag:"deepview"` — all Deep View events.
- `data_type:"fs:stat" AND timestamp_desc:"Modification time"` — MFT/
  inode write activity.
- `message:"/tmp/*"` — changes inside `/tmp`.

Timesketch's analysis plugins (e.g., `browser_search`, `similarity`)
operate on these rows identically to Plaso output.

!!! warning "Caveats"
    - **Timezone hygiene.** Timesketch stores timestamps in UTC; ensure
      any `timestamp` column coming out of Deep View is also UTC. The
      recipe above appends `Z` — if your `datetime` is naive or in a
      local zone, convert first.
    - **Row count limits.** Timesketch's default ingest limit is 10M
      rows per timeline. Split filesystem timelines by volume or time
      range before upload.
    - **Retention cost.** Timesketch keeps the raw CSV plus an
      Elasticsearch index; budget disk accordingly. Delete old
      timelines via the sketch UI once the investigation closes.
    - **Schema drift.** `PluginResult.columns` is not a stable public
      API across major versions — if `filesystem_timeline` changes
      column order, the conversion will still work because it indexes
      by name, but tests should pin a Deep View version.
