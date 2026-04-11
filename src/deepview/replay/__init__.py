"""Session recording & replay for trace events.

The replay subsystem persists events from a :class:`TraceEventBus`
into a SQLite database (``json1``-backed) and lets the CLI replay
them back into a private bus at configurable speeds — optionally
with a different filter or classification ruleset. This is what
turns Deep View from a live-only tool into a "run detection over
yesterday's capture" workflow.
"""
from __future__ import annotations

from deepview.replay.circular import CircularEventBuffer
from deepview.replay.recorder import SessionRecorder
from deepview.replay.replayer import SessionReplayer
from deepview.replay.store import SessionReader, SessionStore

__all__ = [
    "CircularEventBuffer",
    "SessionRecorder",
    "SessionReplayer",
    "SessionReader",
    "SessionStore",
]
