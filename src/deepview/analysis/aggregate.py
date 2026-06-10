"""Rolling event aggregation shared by panels and reports.

:class:`EventAggregator` ingests :class:`MonitorEvent`s and maintains the
cheap summaries visualizations need — cumulative per-category and
per-process counts, per-remote network talkers, and fixed-width time-bucket
series for rate sparklines and category heatmaps. It replaces the ad-hoc
deques each dashboard panel used to re-roll, and is O(buckets) per ingest so
it stays cheap under the trace firehose.

All time bucketing keys off ``event.wall_clock_ns`` (falling back to the
wall clock) so a recorded/replayed session aggregates identically to a live
one, which also makes the series deterministic in tests.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from deepview.tracing.events import MonitorEvent

# Network-destination keys, in priority order, as emitted by the various
# tracing backends.
_REMOTE_KEYS = ("daddr", "remote", "dest", "dst")
_LEN_KEYS = ("len", "length", "bytes")


class EventAggregator:
    """Maintain rolling summaries over an event stream."""

    def __init__(
        self,
        *,
        bucket_s: float = 1.0,
        window_buckets: int = 120,
    ) -> None:
        if bucket_s <= 0:
            raise ValueError("bucket_s must be positive")
        self._bucket_ns = int(bucket_s * 1_000_000_000)
        self._window_buckets = max(2, window_buckets)
        self._total = 0
        self._cat_counts: Counter[str] = Counter()
        self._proc_counts: dict[tuple[int, str], int] = {}
        self._talkers: dict[str, list[int]] = {}
        # Finalised per-bucket series (current partial bucket held separately).
        self._rate: deque[int] = deque(maxlen=self._window_buckets)
        self._cat_series: dict[str, deque[int]] = {}
        self._cur_bucket: int | None = None
        self._cur_total = 0
        self._cur_cat: Counter[str] = Counter()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest(self, event: MonitorEvent) -> None:
        """Fold one event into every running summary."""
        now_ns = event.wall_clock_ns or event.timestamp_ns or time.time_ns()
        self._advance(now_ns // self._bucket_ns)

        self._total += 1
        self._cur_total += 1
        category = event.category.value if event.category else "unknown"
        self._cat_counts[category] += 1
        self._cur_cat[category] += 1

        if event.process is not None:
            key = (event.process.pid, event.process.comm)
            self._proc_counts[key] = self._proc_counts.get(key, 0) + 1

        remote = self._remote_of(event)
        if remote is not None:
            stats = self._talkers.setdefault(remote, [0, 0])
            stats[0] += 1
            stats[1] += self._length_of(event)

    def _advance(self, bucket: int) -> None:
        if self._cur_bucket is None:
            self._cur_bucket = bucket
            return
        if bucket <= self._cur_bucket:
            return
        # Flush finalised buckets, filling idle gaps with zeros.
        while self._cur_bucket < bucket:
            self._rate.append(self._cur_total)
            for cat, series in self._cat_series.items():
                series.append(self._cur_cat.get(cat, 0))
            # Categories first seen this bucket need a back-filled series.
            for cat in self._cur_cat:
                if cat not in self._cat_series:
                    series = deque([0] * len(self._rate), maxlen=self._window_buckets)
                    if series:
                        series[-1] = self._cur_cat[cat]
                    else:
                        series.append(self._cur_cat[cat])
                    self._cat_series[cat] = series
            self._cur_total = 0
            self._cur_cat = Counter()
            self._cur_bucket += 1

    @staticmethod
    def _remote_of(event: MonitorEvent) -> str | None:
        for key in _REMOTE_KEYS:
            val = event.args.get(key)
            if val:
                return str(val)
        return None

    @staticmethod
    def _length_of(event: MonitorEvent) -> int:
        for key in _LEN_KEYS:
            val = event.args.get(key)
            if val:
                try:
                    return int(val)
                except (TypeError, ValueError):
                    return 0
        return 0

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def total(self) -> int:
        return self._total

    def category_counts(self) -> dict[str, int]:
        """Cumulative event count per category."""
        return dict(self._cat_counts)

    def top_processes(self, n: int = 10) -> list[tuple[tuple[int, str], int]]:
        """Most active ``(pid, comm)`` pairs by event count."""
        return sorted(self._proc_counts.items(), key=lambda kv: kv[1], reverse=True)[:n]

    def top_talkers(self, n: int = 10) -> list[tuple[str, tuple[int, int]]]:
        """Busiest remote endpoints as ``(remote, (packets, bytes))``."""
        ranked = sorted(
            self._talkers.items(), key=lambda kv: (kv[1][0], kv[1][1]), reverse=True
        )[:n]
        return [(remote, (stats[0], stats[1])) for remote, stats in ranked]

    def rate_series(self, window_s: float | None = None) -> list[int]:
        """Per-bucket event counts (finalised buckets + the current partial)."""
        series = list(self._rate) + [self._cur_total]
        if window_s is not None:
            n = max(1, int(window_s * 1_000_000_000 / self._bucket_ns))
            series = series[-n:]
        return series

    def category_series(self, window_buckets: int | None = None) -> dict[str, list[int]]:
        """Per-category per-bucket counts (finalised + current partial)."""
        out: dict[str, list[int]] = {}
        for cat, series in self._cat_series.items():
            values = list(series) + [self._cur_cat.get(cat, 0)]
            if window_buckets is not None:
                values = values[-window_buckets:]
            out[cat] = values
        # Categories that have only ever appeared in the current bucket.
        for cat, count in self._cur_cat.items():
            if cat not in out:
                out[cat] = [count]
        return out
