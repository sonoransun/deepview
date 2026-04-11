"""Record → replay round-trip tests for the replay subsystem."""
from __future__ import annotations

import asyncio

import pytest

from deepview.core.types import EventCategory, EventSeverity, EventSource, ProcessContext
from deepview.replay.circular import CircularEventBuffer
from deepview.replay.replayer import SessionReplayer
from deepview.replay.store import SessionReader, SessionStore
from deepview.tracing.events import MonitorEvent


def _event(pid: int, nr: int) -> MonitorEvent:
    return MonitorEvent(
        timestamp_ns=pid * 1000 + nr,
        wall_clock_ns=pid * 1_000_000_000 + nr,
        category=EventCategory.SYSCALL_RAW,
        severity=EventSeverity.INFO,
        source=EventSource(platform="linux", backend="test", probe_name="raw_syscalls"),
        process=ProcessContext(pid=pid, tid=pid, ppid=1, uid=0, gid=0, comm=f"comm_{pid}"),
        syscall_name=f"sys_{nr}",
        syscall_nr=nr,
        args={"path": f"/tmp/{pid}_{nr}"},
    )


class TestStoreRoundTrip:
    def test_append_and_read(self, tmp_path):
        db = tmp_path / "session.db"
        store = SessionStore(db)
        sid = store.open_session(hostname="h", kernel="k")
        for i in range(5):
            store.append_event(_event(100, i))
        store.close_session()
        store.close()

        reader = SessionReader(db)
        try:
            sessions = reader.list_sessions()
            assert len(sessions) == 1
            assert sessions[0].event_count == 5

            evs = list(reader.iter_events(session_id=sid))
            assert len(evs) == 5
            assert evs[0].syscall_name == "sys_0"
            assert evs[-1].args == {"path": "/tmp/100_4"}
        finally:
            reader.close()

    def test_filter_by_pid(self, tmp_path):
        db = tmp_path / "session.db"
        store = SessionStore(db)
        sid = store.open_session()
        for pid in (10, 20, 10, 30, 20):
            store.append_event(_event(pid, 1))
        store.close_session()
        store.close()

        reader = SessionReader(db)
        try:
            pid10 = list(reader.iter_events(session_id=sid, pid=10))
            pid20 = list(reader.iter_events(session_id=sid, pid=20))
            assert len(pid10) == 2
            assert len(pid20) == 2
            for ev in pid10:
                assert ev.process.pid == 10
        finally:
            reader.close()

    def test_snapshots_and_alerts(self, tmp_path):
        db = tmp_path / "session.db"
        store = SessionStore(db)
        sid = store.open_session()
        store.append_snapshot("procfs", {"processes": 10})
        store.append_alert(
            rule_id="r1", severity="critical", title="t", event_rowid=None, labels={"k": "v"}
        )
        store.close_session()
        store.close()

        reader = SessionReader(db)
        try:
            snap = reader.latest_snapshot(sid, kind="procfs")
            assert snap == {"processes": 10}
            alerts = reader.list_alerts(sid)
            assert len(alerts) == 1
            assert alerts[0]["rule_id"] == "r1"
            assert alerts[0]["labels"] == {"k": "v"}
        finally:
            reader.close()


class TestCircularBuffer:
    def test_window_drops_old_events(self):
        buf = CircularEventBuffer(window_seconds=1.0)
        # Event A at t=0, event B at t=5s. A should be dropped.
        a = MonitorEvent(wall_clock_ns=0, syscall_name="a")
        b = MonitorEvent(wall_clock_ns=5_000_000_000, syscall_name="b")
        buf.append(a)
        buf.append(b)
        dumped = buf.dump()
        assert len(dumped) == 1
        assert dumped[0] is b


@pytest.mark.asyncio
class TestReplayer:
    async def test_roundtrip_through_replayer(self, tmp_path):
        db = tmp_path / "session.db"
        store = SessionStore(db)
        sid = store.open_session()
        for i in range(3):
            store.append_event(_event(99, i))
        store.close_session()
        store.close()

        reader = SessionReader(db)
        try:
            replayer = SessionReplayer(reader, sid, speed=0.0)
            subscription = replayer.bus.subscribe()

            task = asyncio.create_task(replayer.play(step=True))
            received: list = []
            for _ in range(3):
                ev = await subscription.get(timeout=1.0)
                if ev is None:
                    break
                received.append(ev)
            await task

            assert replayer.stats.events_published == 3
            assert len(received) == 3
            assert received[0].syscall_name == "sys_0"
            assert received[-1].syscall_name == "sys_2"
        finally:
            reader.close()
