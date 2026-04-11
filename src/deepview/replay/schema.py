"""SQLite schema for the Deep View session store.

One database per capture session (ship-of-Theseus style: the CLI can
open it again later for replay). Tables are kept small and JSON is
parked in columns rather than relationally normalised because the
event schema changes faster than the store.
"""
from __future__ import annotations

DDL: str = """
CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    started_ns       INTEGER NOT NULL,
    ended_ns         INTEGER,
    hostname         TEXT,
    kernel           TEXT,
    filter_text      TEXT,
    capabilities_json TEXT,
    dropped          INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    rowid            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    ts_ns            INTEGER NOT NULL,
    wall_ns          INTEGER NOT NULL,
    category         TEXT,
    severity         TEXT,
    source_backend   TEXT,
    source_probe     TEXT,
    pid              INTEGER,
    tid              INTEGER,
    ppid             INTEGER,
    uid              INTEGER,
    comm             TEXT,
    syscall_name     TEXT,
    syscall_nr       INTEGER,
    return_value     INTEGER,
    latency_ns       INTEGER,
    args_json        TEXT,
    labels_json      TEXT
);

CREATE INDEX IF NOT EXISTS events_session_ts_idx
    ON events (session_id, ts_ns);
CREATE INDEX IF NOT EXISTS events_session_pid_idx
    ON events (session_id, pid);
CREATE INDEX IF NOT EXISTS events_session_category_idx
    ON events (session_id, category);

CREATE TABLE IF NOT EXISTS snapshots (
    rowid            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    ts_ns            INTEGER NOT NULL,
    kind             TEXT NOT NULL,
    payload_json     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS snapshots_session_ts_idx
    ON snapshots (session_id, ts_ns);

CREATE TABLE IF NOT EXISTS alerts (
    rowid            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    ts_ns            INTEGER NOT NULL,
    rule_id          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    title            TEXT,
    event_rowid      INTEGER,
    labels_json      TEXT
);

CREATE INDEX IF NOT EXISTS alerts_session_ts_idx
    ON alerts (session_id, ts_ns);
"""
