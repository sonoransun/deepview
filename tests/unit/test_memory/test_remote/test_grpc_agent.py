"""gRPC-path tests for :class:`NetworkAgentProvider`.

These tests require :mod:`grpc` (``pytest.importorskip`` skips the whole
module when it is absent — the common case in CI without the
``remote_acquisition`` extra). They assert the *fallback contract*: with
the generated stubs absent, :func:`_grpc_stubs_available` is ``False`` and
:meth:`NetworkAgentProvider.acquire` still drives the interim framed-TCP
transport end-to-end. The framed-TCP fake-agent pattern is borrowed from
``test_loopback_agent.py``.
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("grpc")

from deepview.core.context import AnalysisContext  # noqa: E402
from deepview.core.types import AcquisitionTarget, DumpFormat  # noqa: E402
from deepview.memory.acquisition.remote.base import RemoteEndpoint  # noqa: E402
from deepview.memory.acquisition.remote.network_agent import (  # noqa: E402
    AGENT_MAGIC,
    AGENT_VERSION,
    NetworkAgentProvider,
    _grpc_stubs_available,
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
        mid = len(payload) // 2
        conn.sendall(struct.pack("!I", mid) + payload[:mid])
        conn.sendall(struct.pack("!I", len(payload) - mid) + payload[mid:])
        conn.sendall(struct.pack("!I", 0))  # EOF sentinel


def _stubs_present() -> bool:
    try:
        from deepview.memory.acquisition.remote import (  # noqa: F401
            deepview_agent_pb2,
            deepview_agent_pb2_grpc,
        )
    except Exception:  # noqa: BLE001
        return False
    return True


def test_grpc_stubs_absent_means_unavailable() -> None:
    # Generated stubs are not committed; with grpc importable but the
    # pb2 modules absent, the helper must report False so acquire() falls
    # back to framed-TCP. (Guard against an environment where someone has
    # generated the stubs locally.)
    if _stubs_present():
        pytest.skip("generated gRPC stubs are present; fallback path not exercised")
    assert _grpc_stubs_available() is False


def test_acquire_falls_back_to_framed_tcp_without_stubs(tmp_path: Path) -> None:
    if _stubs_present():
        pytest.skip("generated gRPC stubs are present; fallback path not exercised")
    assert _grpc_stubs_available() is False

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
    # transport_name is unchanged regardless of which wire is used.
    assert provider.transport_name() == "grpc"
    assert provider.provider_name() == "network-agent"

    output = tmp_path / "agent.raw"
    result = provider.acquire(
        AcquisitionTarget(hostname="127.0.0.1"), output, DumpFormat.RAW
    )
    t.join(timeout=5.0)

    assert result.success is True
    assert result.size_bytes == len(payload)
    assert result.hash_sha256  # SHA256 populated on the fallback path
    assert output.read_bytes() == payload
