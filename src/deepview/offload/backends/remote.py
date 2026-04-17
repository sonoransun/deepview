"""Remote-worker offload backend — stub.

Planned wire format: msgpack-over-TCP with mutual-TLS; an already-
deployed ``deepview-worker`` process consumes :class:`OffloadJob`
payloads and replies with :class:`OffloadResult`. That protocol is
deferred to a later slice — see the offload roadmap in
``/root/.claude/plans/serene-sleeping-starlight.md``.

The stub exists today so:

1. engine registration has a known slot for the remote backend once
   it lands (``engine.register_backend("remote", RemoteWorkerBackend(...))``),
2. ``deepview offload status`` can flag the backend as *unavailable*
   instead of silently omitting it.
"""
from __future__ import annotations

from concurrent.futures import Future

from deepview.offload.backends.base import OffloadBackend
from deepview.offload.jobs import OffloadJob, OffloadResult


class RemoteWorkerBackend(OffloadBackend):
    """Stub for the forthcoming msgpack-over-TCP remote worker pool."""

    _NAME = "remote"

    def __init__(self, endpoint: str = "") -> None:
        # TODO(offload-remote): parse endpoint, establish mTLS channel,
        # handshake with worker, advertise remote capabilities. For now
        # the backend is always unavailable.
        self._endpoint = endpoint

    @property
    def name(self) -> str:
        return self._NAME

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        raise NotImplementedError(
            "RemoteWorkerBackend protocol is not wired yet (deferred slice)"
        )

    def capabilities(self) -> set[str]:
        return {"remote"}

    def is_available(self) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        return None


__all__ = ["RemoteWorkerBackend"]
