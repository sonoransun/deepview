"""Tests for TimelineBuilder aggregation helpers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from deepview.reporting.timeline import TimelineBuilder, TimelineEntry


def _entry(offset_s: float, *, source: str = "trace", severity: str = "info") -> TimelineEntry:
    base = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
    return TimelineEntry(
        timestamp=base + timedelta(seconds=offset_s),
        event_type="x",
        description="d",
        source=source,
        severity=severity,
    )


class TestBucketed:
    def test_counts_per_bucket_including_gaps(self):
        b = TimelineBuilder()
        b.add_entry(_entry(0))
        b.add_entry(_entry(0.5))
        b.add_entry(_entry(3.0))
        buckets = b.bucketed(1.0)
        counts = [c for _, c in buckets]
        # bucket0=2, bucket1=0, bucket2=0, bucket3=1
        assert counts == [2, 0, 0, 1]

    def test_empty_timeline(self):
        assert TimelineBuilder().bucketed(1.0) == []

    def test_rejects_nonpositive_bucket(self):
        import pytest

        with pytest.raises(ValueError):
            TimelineBuilder().bucketed(0)


class TestGaps:
    def test_detects_quiet_intervals(self):
        b = TimelineBuilder()
        b.add_entry(_entry(0))
        b.add_entry(_entry(1))
        b.add_entry(_entry(10))
        gaps = b.gaps(min_gap_s=5)
        assert len(gaps) == 1
        assert gaps[0][2] == 9.0


class TestLanes:
    def test_group_by_source(self):
        b = TimelineBuilder()
        b.add_entry(_entry(0, source="trace"))
        b.add_entry(_entry(1, source="memory"))
        b.add_entry(_entry(2, source="trace"))
        lanes = b.lanes(by="source")
        assert set(lanes) == {"trace", "memory"}
        assert len(lanes["trace"]) == 2

    def test_invalid_lane_key(self):
        import pytest

        with pytest.raises(ValueError):
            TimelineBuilder().lanes(by="nonsense")
