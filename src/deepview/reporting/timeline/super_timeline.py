"""Plaso-compatible super-timeline export."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from deepview.reporting.timeline.event import TimelineEvent


def write_bodyfile(events: Iterable[TimelineEvent], path: Path) -> int:
    """Write a Sleuth Kit bodyfile for ingestion into plaso's psort."""
    lines = [event.bodyfile_line() for event in events]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def write_plaso_csv(events: Iterable[TimelineEvent], path: Path) -> int:
    """Write a CSV compatible with ``psort`` L2T CSV format.

    Columns: ``date,time,timezone,MACB,source,sourcetype,type,user,host,
    short,desc,version,filename,inode,notes,format,extra``. We fill the
    essentials and leave unused fields blank.
    """
    import csv as _csv

    headers = [
        "date",
        "time",
        "timezone",
        "MACB",
        "source",
        "sourcetype",
        "type",
        "user",
        "host",
        "short",
        "desc",
        "version",
        "filename",
        "inode",
        "notes",
        "format",
        "extra",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = _csv.writer(fh)
        writer.writerow(headers)
        count = 0
        for event in events:
            ts = event.timestamp_utc
            writer.writerow(
                [
                    ts.strftime("%m/%d/%Y"),
                    ts.strftime("%H:%M:%S"),
                    "UTC",
                    "M",
                    event.source.value,
                    event.source.value,
                    event.severity.value,
                    "",
                    event.host_id,
                    event.description[:80],
                    event.description,
                    "2",
                    "",
                    "",
                    ",".join(event.mitre_techniques),
                    "deepview",
                    event.entity_id,
                ]
            )
            count += 1
    return count
