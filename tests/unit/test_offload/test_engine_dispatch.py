"""Unit tests for :meth:`OffloadEngine._pick` and ``submit`` backend selection.

Also verifies that :class:`OffloadJobSubmittedEvent` +
:class:`OffloadJobCompletedEvent` fire through the engine's
``context.events`` bus.
"""
from __future__ import annotations

import sys
import threading
from concurrent.futures import Future
from pathlib import Path

import pytest

# Make the shared test helper importable.
_TESTS_ROOT = Path(__file__).resolve().parents[2]
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))

from deepview.core.context import AnalysisContext  # noqa: E402
from deepview.core.events import (  # noqa: E402
    OffloadJobCompletedEvent,
    OffloadJobSubmittedEvent,
)
from deepview.offload.backends.base import OffloadBackend  # noqa: E402
from deepview.offload.engine import OffloadEngine  # noqa: E402
from deepview.offload.jobs import OffloadJob, OffloadResult, make_job  # noqa: E402


# ---------------------------------------------------------------------------
# Stub backend
# ---------------------------------------------------------------------------


class StubBackend(OffloadBackend):
    """Minimal in-process backend that resolves synchronously."""

    def __init__(self, name: str = "custom", caps: set[str] | None = None) -> None:
        self._name = name
        self._caps = caps or {"cpu"}
        self._in_flight = 0
        self._available = True
        self.submit_calls: int = 0

    @property
    def name(self) -> str:
        return self._name

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        self.submit_calls += 1
        fut: Future[OffloadResult] = Future()
        fut.set_result(
            OffloadResult(
                job_id=job.job_id,
                ok=True,
                output=b"ok",
                error=None,
                elapsed_s=0.001,
                backend=self._name,
            )
        )
        return fut

    def capabilities(self) -> set[str]:
        return set(self._caps)

    def is_available(self) -> bool:
        return self._available

    def shutdown(self, wait: bool = True) -> None:
        self._available = False


# ---------------------------------------------------------------------------
# _pick semantics
# ---------------------------------------------------------------------------


def test_default_backend_is_process(context: AnalysisContext) -> None:
    engine = context.offload
    name, backend = engine._pick(None)
    assert name == "process"
    assert backend is engine.backends()["process"]


def test_pick_explicit_thread(context: AnalysisContext) -> None:
    engine = context.offload
    name, backend = engine._pick("thread")
    assert name == "thread"
    assert backend is engine.backends()["thread"]


def test_pick_unknown_backend_raises_key_error(context: AnalysisContext) -> None:
    engine = context.offload
    with pytest.raises(KeyError) as excinfo:
        engine._pick("does-not-exist")
    msg = str(excinfo.value)
    # Error message should list available backends so the operator can recover.
    assert "does-not-exist" in msg
    assert "available" in msg
    assert "process" in msg
    assert "thread" in msg


def test_pick_custom_backend_after_registration(context: AnalysisContext) -> None:
    engine = context.offload
    stub = StubBackend(name="custom")
    engine.register_backend("custom", stub)
    name, backend = engine._pick("custom")
    assert name == "custom"
    assert backend is stub


def test_pick_default_never_auto_selects_gpu(context: AnalysisContext) -> None:
    """Even after registering a GPU-capable stub, the default is process."""
    engine = context.offload
    gpu_stub = StubBackend(name="gpu-opencl", caps={"gpu", "pbkdf2"})
    engine.register_backend("gpu-opencl", gpu_stub)
    name, _ = engine._pick(None)
    assert name == "process"


# ---------------------------------------------------------------------------
# submit lifecycle events
# ---------------------------------------------------------------------------


def test_submit_publishes_submitted_and_completed_events(
    context: AnalysisContext,
) -> None:
    engine = context.offload
    stub = StubBackend(name="stub-sync")
    engine.register_backend("stub-sync", stub)

    submitted: list[OffloadJobSubmittedEvent] = []
    completed: list[OffloadJobCompletedEvent] = []
    done = threading.Event()

    def _on_submit(ev: OffloadJobSubmittedEvent) -> None:
        submitted.append(ev)

    def _on_complete(ev: OffloadJobCompletedEvent) -> None:
        completed.append(ev)
        done.set()

    context.events.subscribe(OffloadJobSubmittedEvent, _on_submit)
    context.events.subscribe(OffloadJobCompletedEvent, _on_complete)

    job = make_job("noop", {"x": 1})
    future = engine.submit(job, backend="stub-sync")

    # The stub resolves synchronously — add_done_callback fires immediately.
    assert done.wait(timeout=1.0)

    # await_result returns the stubbed OffloadResult.
    result = future.await_result(timeout=1.0)
    assert result.ok is True
    assert result.backend == "stub-sync"

    # Exactly one of each event, carrying the right job_id + backend.
    assert len(submitted) == 1
    assert len(completed) == 1
    assert submitted[0].job_id == job.job_id
    assert submitted[0].backend == "stub-sync"
    assert submitted[0].kind == "noop"
    assert completed[0].job_id == job.job_id
    assert completed[0].backend == "stub-sync"
    assert completed[0].ok is True
    assert stub.submit_calls == 1


def test_submit_unknown_backend_bubbles_key_error(
    context: AnalysisContext,
) -> None:
    """Unknown backend raises at submit before any event is published."""
    engine = context.offload

    submitted: list[OffloadJobSubmittedEvent] = []
    context.events.subscribe(OffloadJobSubmittedEvent, submitted.append)

    job = make_job("noop", {})
    with pytest.raises(KeyError):
        engine.submit(job, backend="not-registered")

    # No submit event should have been published for a failed dispatch.
    assert submitted == []


# ---------------------------------------------------------------------------
# Standalone engine (no shared fixture) — belt-and-braces for _pick
# ---------------------------------------------------------------------------


def test_fresh_engine_registers_thread_and_process() -> None:
    ctx = AnalysisContext.for_testing()
    try:
        engine = OffloadEngine(ctx)
        names = set(engine.backends().keys())
        assert {"thread", "process"}.issubset(names)
    finally:
        ctx.offload.shutdown(wait=True)
