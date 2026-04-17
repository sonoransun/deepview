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

from collections.abc import AsyncIterator, Iterable
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

    def _pick(self, backend: str | None) -> tuple[str, OffloadBackend]:
        name = backend or self._default_backend
        if name not in self._backends:
            raise KeyError(
                f"No offload backend registered under {name!r}; "
                f"available: {sorted(self._backends)}"
            )
        return name, self._backends[name]

    def submit(
        self,
        job: OffloadJob[object, object],
        *,
        backend: str | None = None,
    ) -> OffloadFuture[object]:
        """Submit *job* to the named backend (or the default) and return the future.

        Publishes :class:`OffloadJobSubmittedEvent` synchronously before
        scheduling the work and :class:`OffloadJobCompletedEvent` from
        a done-callback attached to the stdlib future. Completion
        events always fire — even when the backend raised an exception
        at submit time is bubbled directly to the caller (no future,
        so no completion event).
        """
        name, chosen = self._pick(backend)
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
    ) -> AsyncIterator[OffloadResult]:
        """Submit *jobs* and async-yield results in completion order."""
        import asyncio

        loop = asyncio.get_running_loop()
        pending: list[OffloadFuture[object]] = [
            self.submit(j, backend=backend) for j in jobs
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
