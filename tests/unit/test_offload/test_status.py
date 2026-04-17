"""Verify engine.status() exposes the built-in backends."""
from __future__ import annotations

from deepview.core.context import AnalysisContext


def test_status_lists_thread_and_process() -> None:
    context = AnalysisContext.for_testing()
    try:
        status = context.offload.status()
        assert "thread" in status
        assert "process" in status
        for name in ("thread", "process"):
            assert status[name]["available"] is True
            caps = status[name]["capabilities"]
            assert "pbkdf2_sha256" in caps
            assert "argon2id" in caps
            assert "sha512" in caps
            assert status[name]["in_flight"] == 0
    finally:
        context.offload.shutdown(wait=True)
