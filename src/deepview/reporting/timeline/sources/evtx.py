"""Windows Event Log (EVTX) source.

Uses the ``python-evtx`` package when installed; otherwise returns no
events. Each EVTX record produces one :class:`TimelineEvent`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from deepview.core.logging import get_logger
from deepview.reporting.timeline.event import Severity, SourceType, TimelineEvent

log = get_logger("reporting.timeline.sources.evtx")


class EvtxSource:
    source_type = SourceType.EVTX

    def __init__(
        self,
        evtx_files: Iterable[Path | str],
        host_id: str = "localhost",
    ) -> None:
        self.files = [Path(p) for p in evtx_files]
        self.host_id = host_id

    def events(self) -> Iterator[TimelineEvent]:
        try:
            import Evtx.Evtx as _evtx  # type: ignore[import-not-found]
        except ImportError:
            log.debug("python_evtx_not_installed")
            return
        for path in self.files:
            if not path.is_file():
                continue
            try:
                with _evtx.Evtx(str(path)) as parser:
                    for record in parser.records():
                        yield from self._parse(path, record)
            except Exception:
                log.exception("evtx_parse_failed", path=str(path))
                continue

    def _parse(self, path: Path, record: object) -> Iterator[TimelineEvent]:
        try:
            xml = record.xml()  # type: ignore[attr-defined]
        except Exception:
            return
        # Minimal XML parse without lxml dep
        event_id = _extract_field(xml, "EventID")
        channel = _extract_field(xml, "Channel")
        ts_iso = _extract_attr(xml, "TimeCreated", "SystemTime")
        if not ts_iso:
            return
        try:
            ts = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        except ValueError:
            return
        yield TimelineEvent(
            timestamp_utc=ts.astimezone(timezone.utc),
            timestamp_source="wall",
            host_id=self.host_id,
            entity_id=f"evtx:{path.name}:{event_id}",
            source=SourceType.EVTX,
            description=f"{channel} EventID={event_id}",
            severity=Severity.LOW,
            raw={"file": path.name, "event_id": event_id, "channel": channel},
        )


def _extract_field(xml: str, tag: str) -> str:
    start = xml.find(f"<{tag}")
    if start == -1:
        return ""
    end_of_tag = xml.find(">", start)
    if end_of_tag == -1:
        return ""
    close = xml.find(f"</{tag}>", end_of_tag)
    if close == -1:
        return ""
    return xml[end_of_tag + 1 : close].strip()


def _extract_attr(xml: str, tag: str, attr: str) -> str:
    idx = xml.find(f"<{tag}")
    if idx == -1:
        return ""
    end_tag = xml.find(">", idx)
    if end_tag == -1:
        return ""
    segment = xml[idx:end_tag]
    attr_marker = f'{attr}="'
    a_idx = segment.find(attr_marker)
    if a_idx == -1:
        return ""
    a_start = a_idx + len(attr_marker)
    a_end = segment.find('"', a_start)
    if a_end == -1:
        return ""
    return segment[a_start:a_end]
