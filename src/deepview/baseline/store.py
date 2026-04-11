"""SQLite-backed snapshot store with content-addressed dedup.

Snapshots can be large (especially when memory digests are included), so we
serialise the snapshot as JSON and store it indexed by ``(host_id, captured_at)``.
When the caller requests a full ``HostSnapshot`` we deserialise on demand.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Iterable

from deepview.baseline.snapshot import HostSnapshot
from deepview.core.exceptions import SnapshotStoreError
from deepview.core.logging import get_logger

log = get_logger("baseline.store")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    platform TEXT,
    kernel TEXT,
    body JSON NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_host_time
    ON snapshots (host_id, captured_at);
"""


class SnapshotStore:
    """Persistent, thread-safe snapshot repository."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------

    def save(self, snapshot: HostSnapshot) -> None:
        body = snapshot.model_dump_json()
        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO snapshots "
                    "(snapshot_id, host_id, captured_at, platform, kernel, body) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        snapshot.snapshot_id,
                        snapshot.host_id,
                        snapshot.captured_at.isoformat(),
                        snapshot.platform,
                        snapshot.kernel,
                        body,
                    ),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise SnapshotStoreError(f"Failed to save snapshot: {exc}") from exc

    def load(self, snapshot_id: str) -> HostSnapshot:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT body FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
            ).fetchone()
        if row is None:
            raise SnapshotStoreError(f"Snapshot not found: {snapshot_id}")
        return HostSnapshot.model_validate_json(row["body"])

    def list_snapshots(self, host_id: str | None = None) -> list[dict[str, object]]:
        with self._lock, self._connect() as conn:
            if host_id:
                rows = conn.execute(
                    "SELECT snapshot_id, host_id, captured_at, platform, kernel "
                    "FROM snapshots WHERE host_id = ? ORDER BY captured_at DESC",
                    (host_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT snapshot_id, host_id, captured_at, platform, kernel "
                    "FROM snapshots ORDER BY captured_at DESC"
                ).fetchall()
        return [dict(row) for row in rows]

    def latest(self, host_id: str) -> HostSnapshot | None:
        items = self.list_snapshots(host_id)
        if not items:
            return None
        return self.load(str(items[0]["snapshot_id"]))

    def delete(self, snapshot_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM snapshots WHERE snapshot_id = ?", (snapshot_id,))
            conn.commit()
