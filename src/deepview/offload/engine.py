"""Top-level offload engine.

The engine is the single thing :class:`~deepview.core.context.AnalysisContext`
lazily constructs as ``context.offload``. It:

- auto-registers the two in-tree backends (:class:`ThreadPoolBackend` +
  :class:`ProcessPoolBackend`) at construction — both are always
  available;
- registers the GPU and remote stubs *only* if their probe succeeds,
  so ``engine.status()`` on a core install reports ``thread`` and
  ``process`` and nothing else;
- publishes :class:`OffloadJobSubmittedEvent` at submit time and
  :class:`OffloadJobCompletedEvent` when the stdlib future resolves —
  both through ``context.events`` so anything subscribed to the
  core :class:`EventBus` (dashboard panels, replay recorder,
  classification pipeline) sees the activity for free.

Default backend is ``"process"`` because every built-in KDF workload
is CPU-bound; callers pass ``backend="thread"`` explicitly for
I/O-heavy work or when the payload is not picklable.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Set
from concurrent.futures import Future
from typing import TYPE_CHECKING

from deepview.core.events import (
    OffloadJobCompletedEvent,
    OffloadJobSubmittedEvent,
)
from deepview.core.logging import get_logger
from deepview.offload.backends.base import OffloadBackend
from deepview.offload.backends.gpu_cuda import CUDABackend
from deepview.offload.backends.gpu_opencl import OpenCLBackend
from deepview.offload.backends.process import ProcessPoolBackend
from deepview.offload.backends.thread import ThreadPoolBackend
from deepview.offload.futures import OffloadFuture
from deepview.offload.jobs import OffloadJob, OffloadResult

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.core.events import EventBus

log = get_logger("offload.engine")


class OffloadEngine:
    """Dispatch :class:`OffloadJob` onto registered backends."""

    def __init__(
        self, context: AnalysisContext, default_backend: str = "process"
    ) -> None:
        self._context = context
        self._backends: dict[str, OffloadBackend] = {}
        self._default_backend = default_backend

        # Thread + process always register — they are stdlib-only.
        self.register_backend("thread", ThreadPoolBackend())
        self.register_backend("process", ProcessPoolBackend())

        # GPU backends: register only if their probe succeeds so
        # ``status()`` output is honest rather than cluttered with
        # unreachable adapters.
        try:
            opencl = OpenCLBackend()
            if opencl.is_available():
                self.register_backend("gpu-opencl", opencl)
        except Exception as exc:  # noqa: BLE001
            log.debug("opencl probe failed", error=str(exc))
        try:
            cuda = CUDABackend()
            if cuda.is_available():
                self.register_backend("gpu-cuda", cuda)
        except Exception as exc:  # noqa: BLE001
            log.debug("cuda probe failed", error=str(exc))

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_backend(self, name: str, backend: OffloadBackend) -> None:
        """Register *backend* under *name* (overwrites on duplicate)."""
        self._backends[name] = backend

    def backends(self) -> dict[str, OffloadBackend]:
        return dict(self._backends)

    # ------------------------------------------------------------------
    # Public accessors (avoid ``getattr(engine, "_context")`` coupling)
    # ------------------------------------------------------------------

    @property
    def context(self) -> AnalysisContext:
        """The :class:`AnalysisContext` this engine was bound to."""
        return self._context

    @property
    def events(self) -> EventBus:
        """Shortcut for ``context.events`` — the core :class:`EventBus`."""
        return self._context.events

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def _resolve_named(self, name: str) -> tuple[str, OffloadBackend]:
        """Resolve an explicit backend *name*, raising :class:`KeyError` if absent."""
        if name not in self._backends:
            raise KeyError(
                f"No offload backend registered under {name!r}; "
                f"available: {sorted(self._backends)}"
            )
        return name, self._backends[name]

    def _first_covering(
        self, requirements: Set[str]
    ) -> tuple[str, OffloadBackend] | None:
        """First registered+available backend whose capabilities cover *requirements*.

        Insertion order is honoured (``thread`` then ``process`` then any
        GPU/remote stubs), so the cheapest always-on backend wins when more
        than one satisfies the requirement set. Backends that are not
        currently available (shut down, GPU device gone) are skipped.
        """
        need = set(requirements)
        for name, backend in self._backends.items():
            if not backend.is_available():
                continue
            if need.issubset(backend.capabilities()):
                return name, backend
        return None

    def select_backend(
        self,
        backend: str | None = None,
        *,
        requirements: Set[str] | None = None,
        io_bound: bool = False,
    ) -> tuple[str, OffloadBackend]:
        """Resolve the ``(name, backend)`` pair a job should run on.

        Selection rules, in priority order:

        1. An explicit *backend* name wins — it is resolved and validated
           (raising :class:`KeyError` when unregistered), regardless of
           the other hints. This preserves the long-standing
           ``submit(job, backend=...)`` contract.
        2. If *requirements* are declared, the first registered backend —
           in insertion order — that is currently available and whose
           :meth:`~OffloadBackend.capabilities` cover the requirement set
           is chosen. If none cover them, a :class:`KeyError` lists what
           was needed and which capabilities are on offer.
        3. Otherwise *io_bound* jobs prefer the ``thread`` backend (when
           registered + available); everything else — and the io_bound
           fall-through — lands on the configured default (``process``).

        GPU/remote backends are therefore *never* auto-selected unless the
        caller either names them explicitly or declares a requirement set
        that only a GPU/remote backend can satisfy.
        """
        if backend is not None:
            return self._resolve_named(backend)

        if requirements:
            match = self._first_covering(requirements)
            if match is not None:
                return match
            offered = {
                name: sorted(b.capabilities())
                for name, b in self._backends.items()
            }
            raise KeyError(
                f"No registered offload backend covers requirements "
                f"{sorted(requirements)}; available capabilities: {offered}"
            )

        if io_bound:
            thread = self._backends.get("thread")
            if thread is not None and thread.is_available():
                return "thread", thread

        return self._resolve_named(self._default_backend)

    def _pick(self, backend: str | None) -> tuple[str, OffloadBackend]:
        """Backwards-compatible shim around :meth:`select_backend`.

        Retained because callers (and tests) still call ``_pick(None)`` /
        ``_pick("thread")`` directly; it is exactly ``select_backend`` with
        no requirement/io hints.
        """
        return self.select_backend(backend)

    def submit(
        self,
        job: OffloadJob[object, object],
        *,
        backend: str | None = None,
        requirements: Set[str] | None = None,
        io_bound: bool = False,
    ) -> OffloadFuture[object]:
        """Submit *job* to the selected backend and return the future.

        The backend is chosen by :meth:`select_backend` from the explicit
        *backend* name (if given), the job *requirements* capability set,
        and the *io_bound* hint — see that method for the full rule order.
        Existing callers that pass only ``backend=`` (or nothing) keep the
        old default-to-``process`` behaviour unchanged.

        Publishes :class:`OffloadJobSubmittedEvent` synchronously before
        scheduling the work and :class:`OffloadJobCompletedEvent` from
        a done-callback attached to the stdlib future. Completion
        events always fire — even when the backend raised an exception
        at submit time is bubbled directly to the caller (no future,
        so no completion event).
        """
        name, chosen = self.select_backend(
            backend, requirements=requirements, io_bound=io_bound
        )
        self._context.events.publish(
            OffloadJobSubmittedEvent(
                job_id=job.job_id,
                kind=job.kind,
                backend=name,
                cost_hint=job.cost_hint,
            )
        )
        stdlib_future: Future[OffloadResult] = chosen.submit(job)

        def _on_done(fut: Future[OffloadResult]) -> None:
            try:
                result = fut.result()
                ok = result.ok
                elapsed = result.elapsed_s
                error = result.error
            except BaseException as exc:  # noqa: BLE001
                ok = False
                elapsed = 0.0
                error = f"{type(exc).__name__}: {exc}"
            self._context.events.publish(
                OffloadJobCompletedEvent(
                    job_id=job.job_id,
                    ok=ok,
                    elapsed_s=elapsed,
                    backend=name,
                    error=error,
                )
            )

        stdlib_future.add_done_callback(_on_done)
        return OffloadFuture(stdlib_future, job.job_id)

    async def submit_many(
        self,
        jobs: Iterable[OffloadJob[object, object]],
        *,
        backend: str | None = None,
        requirements: Set[str] | None = None,
        io_bound: bool = False,
    ) -> AsyncIterator[OffloadResult]:
        """Submit *jobs* and async-yield results in completion order.

        The same backend-selection hints accepted by :meth:`submit`
        (*backend*, *requirements*, *io_bound*) are forwarded to every job.
        """
        import asyncio

        loop = asyncio.get_running_loop()
        pending: list[OffloadFuture[object]] = [
            self.submit(j, backend=backend, requirements=requirements, io_bound=io_bound)
            for j in jobs
        ]
        queue: asyncio.Queue[OffloadResult] = asyncio.Queue()

        def _schedule(fut: OffloadFuture[object]) -> None:
            def _cb(f: OffloadFuture[object]) -> None:
                try:
                    res = f.await_result()
                except BaseException as exc:  # noqa: BLE001
                    res = OffloadResult(
                        job_id=f.job_id,
                        ok=False,
                        output=None,
                        error=f"{type(exc).__name__}: {exc}",
                        elapsed_s=0.0,
                        backend=backend or self._default_backend,
                    )
                loop.call_soon_threadsafe(queue.put_nowait, res)

            fut.add_done_callback(_cb)

        for f in pending:
            _schedule(f)

        for _ in range(len(pending)):
            yield await queue.get()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def status(self) -> dict[str, dict[str, object]]:
        """Return ``{name: {available, capabilities, in_flight}}`` for each backend."""
        return {
            name: {
                "available": b.is_available(),
                "capabilities": sorted(b.capabilities()),
                "in_flight": b.in_flight(),
            }
            for name, b in self._backends.items()
        }

    def shutdown(self, wait: bool = True) -> None:
        """Shut down every registered backend (best-effort)."""
        for name, b in list(self._backends.items()):
            try:
                b.shutdown(wait=wait)
            except Exception as exc:  # noqa: BLE001
                log.debug("backend shutdown raised", backend=name, error=str(exc))


__all__ = ["OffloadEngine"]
