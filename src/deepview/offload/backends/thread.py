"""Thread-pool backend.

Appropriate for I/O-bound offload (remote workers, disk staging) and
for KDFs whose native implementation already releases the GIL
(``hashlib.pbkdf2_hmac``, argon2-cffi's low-level C call). The
process-pool backend is still the default for heavy CPU work — see
:mod:`deepview.offload.backends.process`.

Dispatch is uniform across the thread and process backends: a job
whose ``callable_ref`` is set to ``"module:function"`` has that
callable resolved via :mod:`importlib` and called with ``payload``.
The return value is wrapped into an :class:`OffloadResult`; any
exception is caught and reported as ``ok=False``.
"""
from __future__ import annotations

import importlib
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock

from deepview.offload.backends.base import OffloadBackend
from deepview.offload.jobs import OffloadJob, OffloadResult


def _resolve_callable(callable_ref: str) -> object:
    """Resolve ``"module.path:function"`` to the referenced callable."""
    if ":" not in callable_ref:
        raise ValueError(
            f"callable_ref must be 'module:function', got: {callable_ref!r}"
        )
    mod_path, func_name = callable_ref.rsplit(":", 1)
    module = importlib.import_module(mod_path)
    try:
        return getattr(module, func_name)
    except AttributeError as e:
        raise AttributeError(
            f"module {mod_path!r} has no attribute {func_name!r}"
        ) from e


def _run_job(job: OffloadJob[object, object], backend_name: str) -> OffloadResult:
    """Execute *job* in the current thread and wrap the outcome."""
    started = time.perf_counter()
    if job.callable_ref is None:
        return OffloadResult(
            job_id=job.job_id,
            ok=False,
            output=None,
            error="callable_ref is required for thread/process backends",
            elapsed_s=time.perf_counter() - started,
            backend=backend_name,
        )
    try:
        func = _resolve_callable(job.callable_ref)
        if not callable(func):
            raise TypeError(f"{job.callable_ref!r} is not callable")
        output = func(job.payload)
    except BaseException as exc:  # noqa: BLE001 — backend is the error firewall
        return OffloadResult(
            job_id=job.job_id,
            ok=False,
            output=None,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_s=time.perf_counter() - started,
            backend=backend_name,
        )
    return OffloadResult(
        job_id=job.job_id,
        ok=True,
        output=output,
        error=None,
        elapsed_s=time.perf_counter() - started,
        backend=backend_name,
    )


class ThreadPoolBackend(OffloadBackend):
    """:class:`concurrent.futures.ThreadPoolExecutor`-backed offload pool."""

    _NAME = "thread"
    _CAPS: frozenset[str] = frozenset(
        {"io", "pbkdf2_sha256", "argon2id", "sha512", "custom"}
    )

    def __init__(self, max_workers: int | None = None) -> None:
        self._max_workers = max_workers or os.cpu_count() or 1
        self._executor: ThreadPoolExecutor | None = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="deepview-offload-thread",
        )
        self._in_flight = 0
        self._lock = Lock()

    @property
    def name(self) -> str:
        return self._NAME

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        if self._executor is None:
            raise RuntimeError("ThreadPoolBackend has been shut down")
        with self._lock:
            self._in_flight += 1
        future: Future[OffloadResult] = self._executor.submit(
            _run_job, job, self._NAME
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


__all__ = ["ThreadPoolBackend"]
