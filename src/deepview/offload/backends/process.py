"""Process-pool backend — primary CPU worker pool.

The process pool escapes the GIL and is the *default* backend in
:class:`deepview.offload.engine.OffloadEngine` for exactly this reason:
PBKDF2 / Argon2id / bulk SHA-512 are CPU-bound and scale near-linearly
with core count when run in separate interpreters.

Constraints imposed by :mod:`concurrent.futures.ProcessPoolExecutor`:

- The dispatch helper (:func:`_dispatch`) has to be a module-level
  function so it can be pickled and shipped to the worker.
- The job payload and the callable's return value must both be
  pickle-safe. Thin ``dict`` / ``bytes`` payloads (as produced by
  :mod:`deepview.offload.kdf`) satisfy this.
- A backend-local import of the referenced callable is performed
  *inside* the worker process via :mod:`importlib` — the engine never
  ships a live function object across the pickle boundary.
"""
from __future__ import annotations

import importlib
import os
import time
from concurrent.futures import Future, ProcessPoolExecutor
from threading import Lock

from deepview.offload.backends.base import OffloadBackend
from deepview.offload.jobs import OffloadJob, OffloadResult

_BACKEND_NAME = "process"


def _dispatch(callable_ref: str | None, payload: object, job_id: str) -> OffloadResult:
    """Top-level worker entry point. Must be picklable.

    Accepts the already-extracted fields of an :class:`OffloadJob`
    rather than the job itself because the dataclass is frozen +
    slotted and is not guaranteed to be importable by name in the
    worker (it is, but keeping the signature primitive makes the wire
    format version-stable).
    """
    started = time.perf_counter()
    if callable_ref is None:
        return OffloadResult(
            job_id=job_id,
            ok=False,
            output=None,
            error="callable_ref is required for process backend",
            elapsed_s=time.perf_counter() - started,
            backend=_BACKEND_NAME,
        )
    try:
        if ":" not in callable_ref:
            raise ValueError(
                f"callable_ref must be 'module:function', got: {callable_ref!r}"
            )
        mod_path, func_name = callable_ref.rsplit(":", 1)
        module = importlib.import_module(mod_path)
        func = getattr(module, func_name)
        if not callable(func):
            raise TypeError(f"{callable_ref!r} is not callable")
        output = func(payload)
    except BaseException as exc:  # noqa: BLE001
        return OffloadResult(
            job_id=job_id,
            ok=False,
            output=None,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_s=time.perf_counter() - started,
            backend=_BACKEND_NAME,
        )
    return OffloadResult(
        job_id=job_id,
        ok=True,
        output=output,
        error=None,
        elapsed_s=time.perf_counter() - started,
        backend=_BACKEND_NAME,
    )


class ProcessPoolBackend(OffloadBackend):
    """:class:`concurrent.futures.ProcessPoolExecutor`-backed offload pool."""

    _NAME = _BACKEND_NAME
    _CAPS: frozenset[str] = frozenset(
        {"io", "pbkdf2_sha256", "argon2id", "sha512", "custom", "picklable"}
    )

    def __init__(self, max_workers: int | None = None) -> None:
        self._max_workers = max_workers or os.cpu_count() or 1
        self._executor: ProcessPoolExecutor | None = ProcessPoolExecutor(
            max_workers=self._max_workers,
        )
        self._in_flight = 0
        self._lock = Lock()

    @property
    def name(self) -> str:
        return self._NAME

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        if self._executor is None:
            raise RuntimeError("ProcessPoolBackend has been shut down")
        with self._lock:
            self._in_flight += 1
        future: Future[OffloadResult] = self._executor.submit(
            _dispatch, job.callable_ref, job.payload, job.job_id
        )
        future.add_done_callback(self._on_done)
        return future

    def _on_done(self, _future: Future[OffloadResult]) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)

    def capabilities(self) -> set[str]:
        return set(self._CAPS)

    def is_available(self) -> bool:
        return self._executor is not None

    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    def shutdown(self, wait: bool = True) -> None:
        if self._executor is None:
            return
        self._executor.shutdown(wait=wait)
        self._executor = None


__all__ = ["ProcessPoolBackend"]
