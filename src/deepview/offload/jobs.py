"""Offload job + result dataclasses.

These are the two typed value objects that travel through the offload
subsystem. An :class:`OffloadJob` is what the caller submits to the
engine; an :class:`OffloadResult` is what the worker (thread / process /
GPU / remote) returns when the job finishes.

The dataclasses are deliberately tiny and backend-agnostic — every
backend has its own internals, but the job/result pair is the shared
wire format that flows through ``engine.submit()`` and out of the
matching :class:`~concurrent.futures.Future`.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Generic, TypeVar

InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")


@dataclass(frozen=True, slots=True, eq=False)
class OffloadJob(Generic[InputT, OutputT]):
    """Unit of work submitted to the offload engine.

    Parameters
    ----------
    job_id:
        Unique identifier; callers typically let :func:`make_job` fill
        this in with a fresh ``uuid4().hex``.
    kind:
        Logical kind of work (``"pbkdf2_sha256"``, ``"argon2id"``, ...);
        used for bookkeeping and selecting benchmark shapes.
    payload:
        Backend-specific input. For the built-in KDF workers it is a
        plain ``dict`` of str-keyed parameters; for custom callables it
        is whatever the callable accepts.
    callable_ref:
        ``"module:function"`` reference resolved via :mod:`importlib`
        by the thread / process backends. ``None`` means the backend
        selects the handler implicitly from *kind*.
    cost_hint:
        Relative cost (1 = cheap). Used by schedulers that care about
        balancing — the built-in engine just records it in the
        submitted event.
    deadline_s:
        Optional wall-clock deadline in seconds from submission. The
        built-in backends don't enforce this; they record it so remote
        / GPU backends can reject an expired job.
    """

    job_id: str
    kind: str
    payload: object
    callable_ref: str | None = None
    cost_hint: int = 1
    deadline_s: float | None = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OffloadJob):
            return NotImplemented
        return self.job_id == other.job_id

    def __hash__(self) -> int:
        return hash(self.job_id)


@dataclass(frozen=True, slots=True)
class OffloadResult(Generic[OutputT]):
    """Outcome of an offloaded job.

    ``ok`` is ``True`` on success and ``output`` carries the backend's
    return value; ``ok`` is ``False`` on failure and ``error`` carries
    a human-readable stringified exception. ``elapsed_s`` is measured
    by whichever backend ran the job and ``backend`` is the registered
    backend name so consumers can tell the two pools apart.
    """

    job_id: str
    ok: bool
    output: object | None
    error: str | None
    elapsed_s: float
    backend: str


def make_job(
    kind: str,
    payload: object,
    *,
    callable_ref: str | None = None,
    cost_hint: int = 1,
    deadline_s: float | None = None,
) -> OffloadJob[object, object]:
    """Build an :class:`OffloadJob` with a fresh unique ``job_id``."""
    return OffloadJob(
        job_id=uuid.uuid4().hex,
        kind=kind,
        payload=payload,
        callable_ref=callable_ref,
        cost_hint=cost_hint,
        deadline_s=deadline_s,
    )


__all__ = ["OffloadJob", "OffloadResult", "make_job", "InputT", "OutputT"]
