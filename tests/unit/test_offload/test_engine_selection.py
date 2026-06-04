"""Unit tests for :class:`OffloadEngine` capability-driven backend selection.

These exercise :meth:`OffloadEngine.select_backend` (and the
backwards-compatible :meth:`_pick` shim) directly with fake backends so
the selection rules are pinned without spinning real thread/process
pools beyond the two the engine always registers:

1. an explicit ``backend=`` name always wins (and validates registration);
2. a declared *requirements* capability set picks the first
   registered + available backend whose ``capabilities()`` cover it,
   in insertion order;
3. ``io_bound`` jobs fall back to ``thread``; everything else to the
   ``process`` default;
4. GPU/remote backends are never auto-selected without an explicit name
   or a requirement only they satisfy;
5. unavailable backends are skipped during requirement matching.
"""
from __future__ import annotations

from concurrent.futures import Future

import pytest

from deepview.core.context import AnalysisContext
from deepview.offload.backends.base import OffloadBackend
from deepview.offload.engine import OffloadEngine
from deepview.offload.jobs import OffloadJob, OffloadResult, make_job


# ---------------------------------------------------------------------------
# Fake backend
# ---------------------------------------------------------------------------


class FakeBackend(OffloadBackend):
    """In-process backend resolving synchronously, with tunable caps/availability."""

    def __init__(
        self,
        name: str,
        caps: set[str] | None = None,
        *,
        available: bool = True,
    ) -> None:
        self._name = name
        self._caps = caps if caps is not None else {"cpu"}
        self._available = available
        self.submit_calls = 0

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
                elapsed_s=0.0,
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
# select_backend: explicit name wins
# ---------------------------------------------------------------------------


def test_explicit_name_wins_over_requirements(context: AnalysisContext) -> None:
    engine = context.offload
    fake = FakeBackend("gpu-fake", caps={"gpu", "pbkdf2_sha256"})
    engine.register_backend("gpu-fake", fake)

    # Even with requirements that the default process backend satisfies,
    # an explicit name takes precedence.
    name, backend = engine.select_backend(
        "gpu-fake", requirements={"pbkdf2_sha256"}
    )
    assert name == "gpu-fake"
    assert backend is fake


def test_explicit_name_wins_over_io_bound(context: AnalysisContext) -> None:
    engine = context.offload
    name, _ = engine.select_backend("process", io_bound=True)
    assert name == "process"


def test_explicit_unknown_name_raises_keyerror(context: AnalysisContext) -> None:
    engine = context.offload
    with pytest.raises(KeyError) as excinfo:
        engine.select_backend("nope", requirements={"cpu"}, io_bound=True)
    msg = str(excinfo.value)
    assert "nope" in msg
    assert "available" in msg


# ---------------------------------------------------------------------------
# select_backend: requirements coverage
# ---------------------------------------------------------------------------


def test_requirements_pick_first_covering_in_insertion_order(
    context: AnalysisContext,
) -> None:
    """Both thread and process cover the KDF caps; thread registered first wins."""
    engine = context.offload
    name, backend = engine.select_backend(requirements={"pbkdf2_sha256"})
    assert name == "thread"
    assert backend is engine.backends()["thread"]


def test_requirements_only_satisfied_by_specific_backend(
    context: AnalysisContext,
) -> None:
    """A cap that only the GPU fake advertises routes the job there."""
    engine = context.offload
    gpu = FakeBackend("gpu-fake", caps={"gpu", "argon2-gpu"})
    engine.register_backend("gpu-fake", gpu)

    name, backend = engine.select_backend(requirements={"argon2-gpu"})
    assert name == "gpu-fake"
    assert backend is gpu


def test_requirements_picklable_routes_to_process(context: AnalysisContext) -> None:
    """``picklable`` is advertised by process but not thread (insertion order)."""
    engine = context.offload
    name, backend = engine.select_backend(requirements={"picklable"})
    assert name == "process"
    assert backend is engine.backends()["process"]


def test_requirements_multi_cap_subset(context: AnalysisContext) -> None:
    """A multi-cap requirement set must be fully covered (subset) by the backend."""
    engine = context.offload
    # Both caps are on the process backend; thread also has both -> thread first.
    name, _ = engine.select_backend(requirements={"pbkdf2_sha256", "sha512"})
    assert name == "thread"


def test_requirements_uncoverable_raises_keyerror(context: AnalysisContext) -> None:
    engine = context.offload
    with pytest.raises(KeyError) as excinfo:
        engine.select_backend(requirements={"no-such-capability"})
    msg = str(excinfo.value)
    assert "no-such-capability" in msg
    # The error surfaces what each backend offers so the operator can recover.
    assert "capabilities" in msg


def test_requirements_skip_unavailable_backend(context: AnalysisContext) -> None:
    """An unavailable backend that would otherwise match is skipped."""
    engine = context.offload
    # Register a high-priority-named fake that is NOT available; a second
    # available fake with the same cap must be chosen instead.
    down = FakeBackend("aaa-down", caps={"special"}, available=False)
    up = FakeBackend("zzz-up", caps={"special"})
    engine.register_backend("aaa-down", down)
    engine.register_backend("zzz-up", up)

    name, backend = engine.select_backend(requirements={"special"})
    assert name == "zzz-up"
    assert backend is up


def test_empty_requirements_set_is_treated_as_no_requirements(
    context: AnalysisContext,
) -> None:
    """An empty set is falsy -> falls through to the default, not 'first backend'."""
    engine = context.offload
    name, _ = engine.select_backend(requirements=set())
    assert name == "process"


# ---------------------------------------------------------------------------
# select_backend: io_bound fallback + default
# ---------------------------------------------------------------------------


def test_io_bound_falls_back_to_thread(context: AnalysisContext) -> None:
    engine = context.offload
    name, backend = engine.select_backend(io_bound=True)
    assert name == "thread"
    assert backend is engine.backends()["thread"]


def test_default_is_process(context: AnalysisContext) -> None:
    engine = context.offload
    name, backend = engine.select_backend()
    assert name == "process"
    assert backend is engine.backends()["process"]


def test_requirements_take_precedence_over_io_bound(
    context: AnalysisContext,
) -> None:
    """When both hints are present, requirements win over the io_bound thread pref."""
    engine = context.offload
    name, _ = engine.select_backend(requirements={"picklable"}, io_bound=True)
    # picklable only on process -> requirements override io_bound's thread pref.
    assert name == "process"


def test_io_bound_skips_unavailable_thread(context: AnalysisContext) -> None:
    """If the thread backend is shut down, io_bound falls through to default."""
    engine = context.offload
    engine.backends()["thread"].shutdown(wait=True)
    name, _ = engine.select_backend(io_bound=True)
    assert name == "process"


# ---------------------------------------------------------------------------
# GPU is never auto-selected without an explicit ask
# ---------------------------------------------------------------------------


def test_gpu_never_auto_selected_by_default(context: AnalysisContext) -> None:
    engine = context.offload
    engine.register_backend(
        "gpu-fake", FakeBackend("gpu-fake", caps={"gpu", "pbkdf2_sha256"})
    )
    assert engine.select_backend()[0] == "process"
    assert engine.select_backend(io_bound=True)[0] == "thread"


# ---------------------------------------------------------------------------
# _pick backwards-compatibility shim
# ---------------------------------------------------------------------------


def test_pick_shim_default(context: AnalysisContext) -> None:
    engine = context.offload
    assert engine._pick(None)[0] == "process"


def test_pick_shim_explicit(context: AnalysisContext) -> None:
    engine = context.offload
    assert engine._pick("thread")[0] == "thread"


def test_pick_shim_unknown_raises(context: AnalysisContext) -> None:
    engine = context.offload
    with pytest.raises(KeyError):
        engine._pick("does-not-exist")


# ---------------------------------------------------------------------------
# submit() honours the hints and routes to the chosen backend
# ---------------------------------------------------------------------------


def test_submit_routes_by_requirements(context: AnalysisContext) -> None:
    engine = context.offload
    gpu = FakeBackend("gpu-fake", caps={"argon2-gpu"})
    engine.register_backend("gpu-fake", gpu)

    job = make_job("argon2", {}, callable_ref="builtins:bool")
    fut = engine.submit(job, requirements={"argon2-gpu"})
    result = fut.await_result(timeout=2.0)

    assert gpu.submit_calls == 1
    assert result.backend == "gpu-fake"


def test_submit_io_bound_routes_to_thread(context: AnalysisContext) -> None:
    engine = context.offload
    # builtins:bool(payload) -> deterministic, no optional deps.
    job = make_job("noop", {}, callable_ref="builtins:bool")
    fut = engine.submit(job, io_bound=True)
    result = fut.await_result(timeout=2.0)
    assert result.backend == "thread"


def test_submit_explicit_backend_overrides_hints(context: AnalysisContext) -> None:
    engine = context.offload
    stub = FakeBackend("named", caps={"cpu"})
    engine.register_backend("named", stub)

    job = make_job("noop", {})
    fut = engine.submit(job, backend="named", io_bound=True, requirements={"cpu"})
    result = fut.await_result(timeout=2.0)
    assert stub.submit_calls == 1
    assert result.backend == "named"


def test_submit_default_unchanged_for_legacy_callers(
    context: AnalysisContext,
) -> None:
    """A bare submit(job) still lands on the process default (no regression)."""
    engine = context.offload
    job = make_job("noop", {}, callable_ref="builtins:bool")
    fut = engine.submit(job)
    result = fut.await_result(timeout=5.0)
    assert result.backend == "process"


# ---------------------------------------------------------------------------
# Standalone engine — belt-and-braces without the shared fixture
# ---------------------------------------------------------------------------


def test_standalone_engine_selection() -> None:
    ctx = AnalysisContext.for_testing()
    try:
        engine = OffloadEngine(ctx)
        assert engine.select_backend()[0] == "process"
        assert engine.select_backend(io_bound=True)[0] == "thread"
        assert engine.select_backend(requirements={"sha512"})[0] == "thread"
    finally:
        ctx.offload.shutdown(wait=True)
