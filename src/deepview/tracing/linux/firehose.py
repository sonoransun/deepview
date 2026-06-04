"""User-space firehose guard for the eBPF poll thread.

The Linux eBPF backend's poll thread (:mod:`deepview.tracing.providers.ebpf`)
calls a user-space callback for *every* perf-buffer event. When a single-PID
or single-UID guard is baked into the BPF source the kernel sheds most of the
load, but the un-narrowed firehose (``raw_syscalls`` with no staged filter)
still overwhelms the poll thread: every event allocates a Pydantic
``MonitorEvent`` before the bounded queue can drop it.

This module is the *pure-Python* decision seam for that path. It owns no bcc
state and never buffers events -- it answers a single question per raw event:
"should the poll thread materialise this event, or shed it now?" The poll
thread keeps the answer cheap (a couple of integer comparisons) and the drop
is *visible* via :attr:`FirehoseGuard.dropped` so it can be surfaced through
``BackendStats.events_dropped`` exactly like the perf-buffer ``lost_cb`` path.

Design contract (mirrors the project-wide drop-on-overflow rule):

* **No buffering.** The guard holds counters only; a "drop" is an immediate
  reject, never a deferred replay.
* **Narrowed runs are never sampled.** When a kernel-side allowlist (PID / UID
  / comm / syscall) is staged, the kernel has already shed the firehose, so
  every surviving event is kept. Sampling only ever kicks in for the
  un-narrowed firehose.
* **Adaptive, deterministic stride.** Under firehose load the guard keeps a
  1-in-``stride`` deterministic sample. The stride climbs as the *observed*
  load (events offered between samples) crosses configured thresholds, so a
  quiet probe stays lossless while a busy one degrades gracefully instead of
  thrashing the bounded queue.

The decision logic is fully unit-testable without bcc: feed it counts and
``has_kernel_narrowing`` and assert which events it keeps.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Default sampling stride ladder. Each tuple is (load_threshold, stride):
# once the number of events offered since the guard last reset crosses
# ``load_threshold``, the keep-ratio becomes 1-in-``stride``. The ladder is
# scanned high-to-low, so the highest crossed threshold wins. A stride of 1
# means "keep everything" (lossless); larger strides shed more aggressively.
_DEFAULT_LADDER: tuple[tuple[int, int], ...] = (
    (0, 1),          # quiet: keep everything
    (50_000, 4),     # busy: keep 1-in-4
    (200_000, 16),   # firehose: keep 1-in-16
    (1_000_000, 64),  # screaming: keep 1-in-64
)


def stride_for_load(
    offered: int,
    ladder: tuple[tuple[int, int], ...] = _DEFAULT_LADDER,
) -> int:
    """Return the sampling stride for a given offered-event count.

    Scans ``ladder`` (assumed sorted ascending by threshold) and returns the
    stride of the highest threshold that ``offered`` has reached. Always
    returns at least 1 (keep everything) so callers never divide by zero.
    """
    stride = 1
    for threshold, candidate in ladder:
        if offered >= threshold:
            stride = candidate
        else:
            break
    return max(1, stride)


@dataclass
class FirehoseGuard:
    """Adaptive 1-in-N sampler + mandatory-narrowing check for the poll path.

    The guard is driven entirely by :meth:`should_keep`, which the poll
    thread calls once per raw perf-buffer event *before* allocating a
    ``MonitorEvent``. It tracks three visible counters:

    * :attr:`offered` -- raw events the guard was asked about.
    * :attr:`kept` -- events the poll thread should materialise.
    * :attr:`dropped` -- events shed by sampling (``offered - kept``).

    ``has_kernel_narrowing`` records whether the active filter staged any
    kernel-side allowlist. When ``True`` the guard never samples: the kernel
    already culled the firehose, so dropping more user-side would lose signal
    the operator explicitly asked for.
    """

    has_kernel_narrowing: bool = False
    ladder: tuple[tuple[int, int], ...] = field(default=_DEFAULT_LADDER)
    offered: int = 0
    kept: int = 0
    dropped: int = 0
    # Monotonic counter of events seen since the last stride recompute; drives
    # the deterministic 1-in-N decision so a sample is taken on a fixed phase
    # rather than relying on a RNG (keeps unit tests deterministic).
    _phase: int = 0
    _stride: int = 1

    def __post_init__(self) -> None:
        # Validate the ladder once so a misconfigured caller fails loudly
        # rather than silently dividing the firehose by a bad stride.
        if not self.ladder or self.ladder[0][0] != 0:
            raise ValueError("ladder must start with a (0, stride) baseline entry")

    @property
    def stride(self) -> int:
        """Current sampling stride (1 == lossless)."""
        return self._stride

    def should_keep(self) -> bool:
        """Decide whether the current raw event should be materialised.

        Returns ``True`` if the poll thread should build a ``MonitorEvent``
        from this perf record, ``False`` if it should shed it now. Updates the
        visible :attr:`offered` / :attr:`kept` / :attr:`dropped` counters and
        recomputes the adaptive stride from the running :attr:`offered` load.

        Narrowed runs (a kernel allowlist is staged) are always kept. The
        un-narrowed firehose keeps a deterministic 1-in-``stride`` slice; the
        very first event after a stride change is always kept so a low-rate
        probe is never starved.
        """
        self.offered += 1

        if self.has_kernel_narrowing:
            self.kept += 1
            return True

        new_stride = stride_for_load(self.offered, self.ladder)
        if new_stride != self._stride:
            # Re-phase on a stride change so the first event under the new
            # stride is sampled immediately (no dead window).
            self._stride = new_stride
            self._phase = 0

        keep = (self._phase % self._stride) == 0
        self._phase += 1

        if keep:
            self.kept += 1
        else:
            self.dropped += 1
        return keep

    def reset(self) -> None:
        """Clear counters and stride state (e.g. between trace sessions)."""
        self.offered = 0
        self.kept = 0
        self.dropped = 0
        self._phase = 0
        self._stride = 1
