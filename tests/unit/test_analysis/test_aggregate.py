"""Tests for the rolling EventAggregator."""
from __future__ import annotations

from deepview.analysis.aggregate import EventAggregator
from deepview.core.types import EventCategory, ProcessContext
from deepview.tracing.events import MonitorEvent


def _event(*, sec: int, category: EventCategory, pid: int = 1, comm: str = "p", **args):
    return MonitorEvent(
        wall_clock_ns=sec * 1_000_000_000,
        category=category,
        process=ProcessContext(pid=pid, tid=pid, ppid=1, uid=0, gid=0, comm=comm),
        args=dict(args),
    )


class TestCounts:
    def test_category_and_total_counts(self):
        agg = EventAggregator()
        agg.ingest(_event(sec=1, category=EventCategory.FILE_IO))
        agg.ingest(_event(sec=1, category=EventCategory.FILE_IO))
        agg.ingest(_event(sec=1, category=EventCategory.NETWORK))
        assert agg.total == 3
        assert agg.category_counts() == {"file_io": 2, "network": 1}

    def test_top_processes(self):
        agg = EventAggregator()
        for _ in range(3):
            agg.ingest(_event(sec=1, category=EventCategory.PROCESS, pid=10, comm="busy"))
        agg.ingest(_event(sec=1, category=EventCategory.PROCESS, pid=20, comm="quiet"))
        top = agg.top_processes(1)
        assert top == [((10, "busy"), 3)]

    def test_top_talkers_counts_packets_and_bytes(self):
        agg = EventAggregator()
        agg.ingest(_event(sec=1, category=EventCategory.NETWORK, daddr="1.2.3.4", len=100))
        agg.ingest(_event(sec=1, category=EventCategory.NETWORK, daddr="1.2.3.4", len=50))
        agg.ingest(_event(sec=1, category=EventCategory.NETWORK, daddr="9.9.9.9", len=10))
        talkers = agg.top_talkers(10)
        assert talkers[0] == ("1.2.3.4", (2, 150))
        assert ("9.9.9.9", (1, 10)) in talkers


class TestSeries:
    def test_rate_series_buckets_by_second(self):
        agg = EventAggregator(bucket_s=1.0)
        agg.ingest(_event(sec=1, category=EventCategory.PROCESS))
        agg.ingest(_event(sec=1, category=EventCategory.PROCESS))
        agg.ingest(_event(sec=2, category=EventCategory.PROCESS))
        # second 1 finalised at 2 events, second 2 is the current partial.
        assert agg.rate_series() == [2, 1]

    def test_rate_series_fills_idle_gaps_with_zero(self):
        agg = EventAggregator(bucket_s=1.0)
        agg.ingest(_event(sec=1, category=EventCategory.PROCESS))
        agg.ingest(_event(sec=4, category=EventCategory.PROCESS))
        # buckets for sec 1,2,3 finalised (1,0,0), sec 4 current (1).
        assert agg.rate_series() == [1, 0, 0, 1]

    def test_category_series_tracks_each_category(self):
        agg = EventAggregator(bucket_s=1.0)
        agg.ingest(_event(sec=1, category=EventCategory.FILE_IO))
        agg.ingest(_event(sec=2, category=EventCategory.FILE_IO))
        agg.ingest(_event(sec=2, category=EventCategory.NETWORK))
        series = agg.category_series()
        assert series["file_io"] == [1, 1]
        # network first seen in bucket 2 (current partial).
        assert series["network"][-1] == 1

    def test_rejects_nonpositive_bucket(self):
        import pytest

        with pytest.raises(ValueError):
            EventAggregator(bucket_s=0)
