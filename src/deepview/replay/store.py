"""SQLite-backed session store (write + read).

Two small classes:

* :class:`SessionStore` — write side. Opens one connection with
  ``PRAGMA journal_mode=WAL`` and batches inserts in short bursts.
  Safe to call from any thread; a ``threading.Lock`` serializes
  access to the underlying connection because sqlite3 in WAL mode
  is still single-connection-per-thread without careful setup.

* :class:`SessionReader` — read side. Opens the same file read-only
  and exposes iterator APIs that the replayer, CLI, and reporting
  subsystems consume.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from deepview.core.logging import get_logger
from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.replay.schema import DDL
from deepview.tracing.events import MonitorEvent

log = get_logger("replay.store")


@dataclass
class SessionInfo:
    id: str
    started_ns: int
    ended_ns: Optional[int]
    hostname: str
    kernel: str
    filter_text: str
    capabilities: dict
    dropped: int
    event_count: int = 0
    alert_count: int = 0


class SessionStore:
    """Append-only SQLite writer for trace events, snapshots, alerts."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(DDL)
        self._conn.commit()
        self._lock = threading.Lock()
        self._session_id: str | None = None
        self._pending: list[tuple] = []
        self._flush_threshold = 1000

    @property
    def path(self) -> Path:
        return self._path

    def open_session(
        self,
        *,
        hostname: str = "",
        kernel: str = "",
        filter_text: str = "",
        capabilities: dict | None = None,
    ) -> str:
        session_id = uuid.uuid4().hex[:12]
        started_ns = time.time_ns()
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (id, started_ns, hostname, kernel, filter_text, capabilities_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    started_ns,
                    hostname,
                    kernel,
                    filter_text,
                    json.dumps(capabilities or {}),
                ),
            )
            self._conn.commit()
            self._session_id = session_id
        log.info("session_opened", id=session_id, path=str(self._path))
        return session_id

    def close_session(self, *, dropped: int = 0) -> None:
        if self._session_id is None:
            return
        self.flush()
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET ended_ns = ?, dropped = ? WHERE id = ?",
                (time.time_ns(), dropped, self._session_id),
            )
            self._conn.commit()
        log.info("session_closed", id=self._session_id, dropped=dropped)
        self._session_id = None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def append_event(self, event: MonitorEvent) -> None:
        if self._session_id is None:
            raise RuntimeError("No session open. Call open_session() first.")
        proc = event.process
        row = (
            self._session_id,
            int(event.timestamp_ns),
            int(event.wall_clock_ns),
            event.category.value if event.category else "",
            event.severity.value if event.severity else "",
            event.source.backend if event.source else "",
            event.source.probe_name if event.source else "",
            int(proc.pid) if proc else 0,
            int(proc.tid) if proc else 0,
            int(proc.ppid) if proc else 0,
            int(proc.uid) if proc else 0,
            proc.comm if proc else "",
            event.syscall_name,
            int(event.syscall_nr),
            int(event.return_value) if event.return_value is not None else None,
            int(event.latency_ns),
            json.dumps(_json_safe(event.args)),
            json.dumps(_json_safe(event.metadata.get("classifications", []))),
        )
        with self._lock:
            self._pending.append(row)
            if len(self._pending) >= self._flush_threshold:
                self._flush_locked()

    def append_snapshot(self, kind: str, payload: dict) -> None:
        if self._session_id is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO snapshots (session_id, ts_ns, kind, payload_json) VALUES (?, ?, ?, ?)",
                (self._session_id, time.time_ns(), kind, json.dumps(_json_safe(payload))),
            )
            self._conn.commit()

    def append_alert(
        self,
        *,
        rule_id: str,
        severity: str,
        title: str,
        event_rowid: int | None,
        labels: dict,
    ) -> None:
        if self._session_id is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (session_id, ts_ns, rule_id, severity, title, event_rowid, labels_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    self._session_id,
                    time.time_ns(),
                    rule_id,
                    severity,
                    title,
                    event_rowid,
                    json.dumps(labels),
                ),
            )
            self._conn.commit()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._pending:
            return
        self._conn.executemany(
            "INSERT INTO events "
            "(session_id, ts_ns, wall_ns, category, severity, source_backend, source_probe, "
            " pid, tid, ppid, uid, comm, syscall_name, syscall_nr, return_value, latency_ns, "
            " args_json, labels_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._pending,
        )
        self._conn.commit()
        self._pending.clear()

    def close(self) -> None:
        self.close_session()
        with self._lock:
            self._conn.close()


class SessionReader:
    """Read-only view of a session store used by the replayer/CLI."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._conn = sqlite3.connect(
            f"file:{self._path}?mode=ro", uri=True, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row

    @property
    def path(self) -> Path:
        return self._path

    def list_sessions(self) -> list[SessionInfo]:
        rows = list(
            self._conn.execute(
                "SELECT id, started_ns, ended_ns, hostname, kernel, filter_text, "
                "capabilities_json, dropped FROM sessions ORDER BY started_ns"
            )
        )
        out: list[SessionInfo] = []
        for r in rows:
            event_count = self._conn.execute(
                "SELECT COUNT(1) FROM events WHERE session_id = ?", (r["id"],)
            ).fetchone()[0]
            alert_count = self._conn.execute(
                "SELECT COUNT(1) FROM alerts WHERE session_id = ?", (r["id"],)
            ).fetchone()[0]
            caps: dict = {}
            try:
                caps = json.loads(r["capabilities_json"] or "{}")
            except json.JSONDecodeError:
                caps = {}
            out.append(
                SessionInfo(
                    id=r["id"],
                    started_ns=r["started_ns"],
                    ended_ns=r["ended_ns"],
                    hostname=r["hostname"] or "",
                    kernel=r["kernel"] or "",
                    filter_text=r["filter_text"] or "",
                    capabilities=caps,
                    dropped=r["dropped"] or 0,
                    event_count=event_count,
                    alert_count=alert_count,
                )
            )
        return out

    def iter_events(
        self,
        session_id: str | None = None,
        *,
        start_ns: int | None = None,
        end_ns: int | None = None,
        pid: int | None = None,
        category: str | None = None,
    ) -> Iterator[MonitorEvent]:
        clauses: list[str] = []
        params: list = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if start_ns is not None:
            clauses.append("ts_ns >= ?")
            params.append(start_ns)
        if end_ns is not None:
            clauses.append("ts_ns <= ?")
            params.append(end_ns)
        if pid is not None:
            clauses.append("pid = ?")
            params.append(pid)
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query = (
            "SELECT ts_ns, wall_ns, category, severity, source_backend, source_probe, "
            "pid, tid, ppid, uid, comm, syscall_name, syscall_nr, return_value, "
            "latency_ns, args_json, labels_json FROM events" + where + " ORDER BY ts_ns"
        )
        for row in self._conn.execute(query, params):
            yield _row_to_event(row)

    def latest_snapshot(self, session_id: str, *, kind: str | None = None) -> dict | None:
        clauses = ["session_id = ?"]
        params: list = [session_id]
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        row = self._conn.execute(
            "SELECT payload_json FROM snapshots WHERE "
            + " AND ".join(clauses)
            + " ORDER BY ts_ns DESC LIMIT 1",
            params,
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None

    def list_alerts(self, session_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts_ns, rule_id, severity, title, labels_json FROM alerts "
            "WHERE session_id = ? ORDER BY ts_ns",
            (session_id,),
        )
        out: list[dict] = []
        for r in rows:
            try:
                labels = json.loads(r["labels_json"] or "{}")
            except json.JSONDecodeError:
                labels = {}
            out.append(
                {
                    "ts_ns": r["ts_ns"],
                    "rule_id": r["rule_id"],
                    "severity": r["severity"],
                    "title": r["title"],
                    "labels": labels,
                }
            )
        return out

    def close(self) -> None:
        self._conn.close()


def _row_to_event(row: sqlite3.Row) -> MonitorEvent:
    try:
        args = json.loads(row["args_json"] or "{}")
    except json.JSONDecodeError:
        args = {}
    try:
        classifications = json.loads(row["labels_json"] or "[]")
    except json.JSONDecodeError:
        classifications = []
    metadata: dict = {"classifications": classifications} if classifications else {}

    try:
        category = EventCategory(row["category"])
    except ValueError:
        category = EventCategory.SYSCALL_RAW
    try:
        severity = EventSeverity(row["severity"])
    except ValueError:
        severity = EventSeverity.INFO

    source = EventSource(
        platform="linux",
        backend=row["source_backend"] or "replay",
        probe_name=row["source_probe"] or "",
    )
    process = ProcessContext(
        pid=row["pid"] or 0,
        tid=row["tid"] or 0,
        ppid=row["ppid"] or 0,
        uid=row["uid"] or 0,
        gid=0,
        comm=row["comm"] or "",
    )
    return MonitorEvent(
        timestamp_ns=row["ts_ns"] or 0,
        wall_clock_ns=row["wall_ns"] or 0,
        category=category,
        severity=severity,
        source=source,
        process=process,
        syscall_name=row["syscall_name"] or "",
        syscall_nr=row["syscall_nr"] if row["syscall_nr"] is not None else -1,
        return_value=row["return_value"],
        latency_ns=row["latency_ns"] or 0,
        args=args,
        metadata=metadata,
    )


def _json_safe(obj):
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(v) for v in obj]
    return str(obj)
