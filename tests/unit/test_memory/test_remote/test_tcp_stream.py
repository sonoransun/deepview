"""End-to-end loopback test for :class:`TCPStreamProvider`.

Spins up a background TCP client that connects to the listening provider
and writes the LiME magic followed by a short payload. Asserts the
output file bytes match and that the detected format is
:class:`DumpFormat.LIME`.
"""
from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    RemoteAcquisitionCompletedEvent,
    RemoteAcquisitionStartedEvent,
)
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.tcp_stream import TCPStreamProvider


def _pick_free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def test_tcp_stream_captures_lime_payload(tmp_path: Path) -> None:
    port = _pick_free_port()
    payload = b"EMiL" + b"\x00" * 28 + b"HELLO-LIME-PAYLOAD"

    context = AnalysisContext.for_testing()
    started: list[RemoteAcquisitionStartedEvent] = []
    completed: list[RemoteAcquisitionCompletedEvent] = []
    context.events.subscribe(RemoteAcquisitionStartedEvent, started.append)
    context.events.subscribe(RemoteAcquisitionCompletedEvent, completed.append)

    endpoint = RemoteEndpoint(
        host="127.0.0.1",
        transport="tcp",
        port=port,
        extra={"bind": "127.0.0.1"},
    )
    provider = TCPStreamProvider(endpoint, context=context)
    output = tmp_path / "capture.lime"

    def _writer() -> None:
        # Give the acquire() call a beat to bind the listener.
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
                    s.sendall(payload)
                    # Half-close write to signal EOF to the server.
                    s.shutdown(socket.SHUT_WR)
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("could not connect to TCPStreamProvider listener")

    t = threading.Thread(target=_writer, daemon=True)
    t.start()
    result = provider.acquire(AcquisitionTarget(hostname="127.0.0.1"), output, DumpFormat.RAW)
    t.join(timeout=5.0)

    assert result.success is True
    assert result.output_path == output
    assert result.format == DumpFormat.LIME
    assert output.read_bytes() == payload
    assert len(started) == 1
    assert len(completed) == 1
    assert completed[0].size_bytes == len(payload)
