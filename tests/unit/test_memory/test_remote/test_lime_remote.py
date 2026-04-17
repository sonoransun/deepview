"""Tests for :class:`LiMERemoteProvider`.

The provider sets up an SSH control channel, a reverse TCP port-forward,
executes ``insmod`` + ``rmmod``, and streams the LiME output back over
the forward. We avoid verifying the byte stream end-to-end (that would
require mocking a file descriptor per chunk) and instead assert the
control-plane commands and that a local listener socket was opened.
"""
from __future__ import annotations

import socket
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("paramiko")

from deepview.core.context import AnalysisContext
from deepview.core.exceptions import AcquisitionError
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.lime_remote import LiMERemoteProvider


def _make_endpoint(tmp_path: Path, **overrides: Any) -> RemoteEndpoint:
    kh = tmp_path / "known_hosts"
    kh.write_text("")
    defaults: dict[str, Any] = {
        "host": "127.0.0.1",
        "transport": "ssh",
        "port": 22,
        "username": "root",
        "known_hosts": kh,
        "extra": {"lime_ko_path": "/tmp/lime.ko", "remote_lime_port": "4444"},
    }
    defaults.update(overrides)
    return RemoteEndpoint(**defaults)


def test_is_available_requires_paramiko() -> None:
    """Availability gates on paramiko importability, nothing else."""
    ctx = AnalysisContext.for_testing()
    ep = RemoteEndpoint(host="127.0.0.1", transport="ssh")
    provider = LiMERemoteProvider(ep, context=ctx)
    assert provider.is_available() is True  # paramiko is imported by the skip above


def test_acquire_refuses_without_known_hosts(tmp_path: Path) -> None:
    """No TOFU: missing known_hosts must abort immediately."""
    ctx = AnalysisContext.for_testing()
    ep = RemoteEndpoint(host="127.0.0.1", transport="ssh")
    provider = LiMERemoteProvider(ep, context=ctx)
    with pytest.raises(AcquisitionError, match="known_hosts"):
        provider.acquire(AcquisitionTarget(hostname=ep.host), tmp_path / "out.lime")


def test_acquire_issues_insmod_and_rmmod_and_opens_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end control-plane assertion.

    Mocks :class:`paramiko.SSHClient` so that calling ``exec_command``
    records the commands issued, and reverse-forwarding is a no-op. A
    background thread connects to the local listener and sends a short
    byte-stream so that :meth:`acquire` completes and writes the output.
    """
    import paramiko

    issued_cmds: list[str] = []
    dummy_stdout = MagicMock()
    dummy_stdout.channel.recv_exit_status = MagicMock(return_value=0)
    dummy_stdout.read = MagicMock(return_value=b"")
    dummy_stderr = MagicMock()

    dummy_transport = MagicMock()
    dummy_transport.request_port_forward = MagicMock(return_value=4444)

    dummy_client = MagicMock()
    dummy_client.get_transport = MagicMock(return_value=dummy_transport)
    dummy_client.load_host_keys = MagicMock()
    dummy_client.set_missing_host_key_policy = MagicMock()
    dummy_client.connect = MagicMock()
    dummy_client.close = MagicMock()

    def fake_exec(cmd: str, *args: Any, **kwargs: Any) -> tuple[Any, Any, Any]:
        issued_cmds.append(cmd)
        return (MagicMock(), dummy_stdout, dummy_stderr)

    dummy_client.exec_command = MagicMock(side_effect=fake_exec)

    monkeypatch.setattr(paramiko, "SSHClient", lambda: dummy_client)

    # Capture the local listener port by snooping on ``socket.socket``.
    created_sockets: list[socket.socket] = []
    real_socket = socket.socket

    def tracking_socket(*a: Any, **kw: Any) -> socket.socket:
        s = real_socket(*a, **kw)
        created_sockets.append(s)
        return s

    monkeypatch.setattr(socket, "socket", tracking_socket)

    ctx = AnalysisContext.for_testing()
    provider = LiMERemoteProvider(_make_endpoint(tmp_path), context=ctx)

    # Drive the dumper: spin a client that connects to the listener once
    # it is bound, sends a handful of bytes, then closes.
    payload = b"EMiL" + b"\x00" * (1024 - 4)

    def feeder() -> None:
        # Wait briefly for listener.bind() to happen.
        for _ in range(200):
            candidate = next(
                (
                    s
                    for s in created_sockets
                    if s.family == socket.AF_INET and s.type == socket.SOCK_STREAM
                ),
                None,
            )
            if candidate is not None:
                try:
                    local_port = candidate.getsockname()[1]
                except OSError:
                    local_port = 0
                if local_port:
                    break
            threading.Event().wait(0.01)
        else:
            return
        try:
            c = real_socket(socket.AF_INET, socket.SOCK_STREAM)
            c.connect(("127.0.0.1", local_port))
            c.sendall(payload)
            c.close()
        except OSError:
            return

    t = threading.Thread(target=feeder, daemon=True)
    t.start()

    out = tmp_path / "out.lime"
    result = provider.acquire(AcquisitionTarget(hostname="127.0.0.1"), out, DumpFormat.LIME)
    t.join(timeout=2.0)

    assert result.success is True
    assert result.format is DumpFormat.LIME
    assert result.output_path == out
    assert result.size_bytes == len(payload)
    assert out.read_bytes() == payload

    # One insmod then one rmmod, in that order.
    insmod = [c for c in issued_cmds if "insmod" in c]
    rmmod = [c for c in issued_cmds if "rmmod" in c]
    assert insmod and "lime.ko" in insmod[0]
    assert "path=tcp:4444" in insmod[0]
    assert "format=lime" in insmod[0]
    assert rmmod and "lime" in rmmod[0]
    assert issued_cmds.index(insmod[0]) < issued_cmds.index(rmmod[0])

    # The reverse port-forward was requested against the operator port.
    dummy_transport.request_port_forward.assert_called_once()
    kwargs = dummy_transport.request_port_forward.call_args.kwargs
    assert kwargs.get("port") == 4444
