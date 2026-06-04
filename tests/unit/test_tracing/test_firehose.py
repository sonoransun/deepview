"""Tests for the user-space firehose guard (pure-Python, no bcc)."""
from __future__ import annotations

import pytest

from deepview.tracing.linux.firehose import (
    FirehoseGuard,
    stride_for_load,
)


class TestStrideForLoad:
    def test_quiet_load_is_lossless(self):
        assert stride_for_load(0) == 1
        assert stride_for_load(100) == 1

    def test_stride_climbs_with_load(self):
        assert stride_for_load(50_000) == 4
        assert stride_for_load(200_000) == 16
        assert stride_for_load(1_000_000) == 64

    def test_highest_crossed_threshold_wins(self):
        # Just past the 200k threshold but not the 1M one.
        assert stride_for_load(999_999) == 16

    def test_never_returns_below_one(self):
        # A degenerate ladder entry must still floor at 1.
        assert stride_for_load(10, ladder=((0, 0),)) == 1

    def test_custom_ladder(self):
        ladder = ((0, 1), (10, 2), (20, 8))
        assert stride_for_load(5, ladder=ladder) == 1
        assert stride_for_load(10, ladder=ladder) == 2
        assert stride_for_load(25, ladder=ladder) == 8


class TestFirehoseGuardNarrowing:
    def test_narrowed_run_keeps_everything(self):
        guard = FirehoseGuard(has_kernel_narrowing=True)
        for _ in range(5000):
            assert guard.should_keep() is True
        assert guard.kept == 5000
        assert guard.dropped == 0
        # Narrowed runs never raise the stride.
        assert guard.stride == 1

    def test_unnarrowed_quiet_run_keeps_everything(self):
        guard = FirehoseGuard(has_kernel_narrowing=False)
        for _ in range(100):
            assert guard.should_keep() is True
        assert guard.kept == 100
        assert guard.dropped == 0


class TestFirehoseGuardSampling:
    def test_drops_become_visible_under_load(self):
        # Tiny ladder so we cross thresholds quickly in the test.
        ladder = ((0, 1), (4, 2))
        guard = FirehoseGuard(has_kernel_narrowing=False, ladder=ladder)

        for _ in range(20):
            guard.should_keep()

        # offered/kept/dropped are consistent and drops are visible.
        assert guard.offered == 20
        assert guard.kept + guard.dropped == guard.offered
        assert guard.dropped > 0
        # Once the stride is 2 we keep roughly half; never buffer.
        assert guard.stride == 2

    def test_deterministic_one_in_n(self):
        # Force stride 2 from the start via a ladder that trips immediately.
        ladder = ((0, 2),)
        guard = FirehoseGuard(has_kernel_narrowing=False, ladder=ladder)
        decisions = [guard.should_keep() for _ in range(10)]
        # Deterministic alternating keep/drop: keep, drop, keep, drop, ...
        assert decisions == [True, False] * 5
        assert guard.kept == 5
        assert guard.dropped == 5

    def test_first_event_after_stride_change_is_kept(self):
        # Ladder jumps to a large stride once offered reaches 3; the event that
        # trips the new stride is re-phased and sampled (no dead window), and
        # the next event under the new stride is shed.
        ladder = ((0, 1), (3, 8))
        guard = FirehoseGuard(has_kernel_narrowing=False, ladder=ladder)
        decisions = [guard.should_keep() for _ in range(5)]
        # Events 1,2 lossless; event 3 trips stride 8 and is re-phased -> kept;
        # events 4,5 are shed under stride 8.
        assert decisions == [True, True, True, False, False]
        assert guard.stride == 8

    def test_no_buffering_invariant(self):
        # The guard exposes only counters: a drop is immediate, never deferred.
        guard = FirehoseGuard(has_kernel_narrowing=False, ladder=((0, 3),))
        kept = sum(1 for _ in range(30) if guard.should_keep())
        assert kept == guard.kept
        assert guard.offered == 30
        assert guard.kept + guard.dropped == 30


class TestFirehoseGuardLifecycle:
    def test_reset_clears_state(self):
        guard = FirehoseGuard(has_kernel_narrowing=False, ladder=((0, 4),))
        for _ in range(40):
            guard.should_keep()
        assert guard.offered == 40
        guard.reset()
        assert guard.offered == 0
        assert guard.kept == 0
        assert guard.dropped == 0
        assert guard.stride == 1

    def test_ladder_must_have_baseline(self):
        with pytest.raises(ValueError):
            FirehoseGuard(ladder=((10, 2),))

    def test_empty_ladder_rejected(self):
        with pytest.raises(ValueError):
            FirehoseGuard(ladder=())
