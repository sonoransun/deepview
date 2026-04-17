"""Loopback test for :class:`NetworkAgentProvider` against a fake agent.

The fake agent speaks the interim framed-TCP protocol documented in
``network_agent.py``: handshake magic+version, then a single ``Acquire``
RPC request, then length-prefixed chunks ending with a zero-length
sentinel. TLS is disabled (``require_tls=False``) since the test is
loopback-only.
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.network_agent import (
    AGENT_MAGIC,
    AGENT_VERSION,
    NetworkAgentProvider,
)


def _pick_free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise RuntimeError("fake-agent: short read")
        buf.extend(c)
    return bytes(buf)


def _run_fake_agent(port: int, payload: bytes, ready: threading.Event) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    try:
        conn, _ = srv.accept()
    finally:
        srv.close()
    with conn:
        hello = _recv_exact(conn, len(AGENT_MAGIC) + 1)
        assert hello[: len(AGENT_MAGIC)] == AGENT_MAGIC
        assert hello[-1] == AGENT_VERSION
        conn.sendall(AGENT_MAGIC + bytes([AGENT_VERSION]))
        (rpc_len,) = struct.unpack("!I", _recv_exact(conn, 4))
        rpc = _recv_exact(conn, rpc_len)
        assert rpc == b"Acquire"
        # Send payload in two chunks to exercise the framed read loop.
        mid = len(payload) // 2
        conn.sendall(struct.pack("!I", mid) + payload[:mid])
        conn.sendall(struct.pack("!I", len(payload) - mid) + payload[mid:])
        conn.sendall(struct.pack("!I", 0))  # EOF sentinel


def test_network_agent_loopback_framed_tcp(tmp_path: Path) -> None:
    payload = bytes(range(256)) * 4  # 1024 bytes
    port = _pick_free_port()
    ready = threading.Event()
    t = threading.Thread(
        target=_run_fake_agent, args=(port, payload, ready), daemon=True
    )
    t.start()
    assert ready.wait(timeout=5.0)
    time.sleep(0.05)  # small grace after bind

    endpoint = RemoteEndpoint(
        host="127.0.0.1",
        transport="grpc",
        port=port,
        require_tls=False,
        tls_ca=None,
    )
    context = AnalysisContext.for_testing()
    provider = NetworkAgentProvider(endpoint, context=context)
    output = tmp_path / "agent.raw"
    result = provider.acquire(
        AcquisitionTarget(hostname="127.0.0.1"), output, DumpFormat.RAW
    )
    t.join(timeout=5.0)

    assert result.success is True
    assert result.size_bytes == len(payload)
    assert output.read_bytes() == payload
