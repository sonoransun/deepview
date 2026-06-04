"""Loopback round-trip tests for :class:`RemoteWorkerBackend`.

A reference worker (:func:`deepview.offload.backends.remote.serve`) runs in
a daemon thread on ``127.0.0.1`` + an ephemeral port with TLS disabled,
mirroring ``tests/unit/test_memory/test_remote/test_loopback_agent.py``.
A real PBKDF2 job is submitted through the backend and its output is
checked against the same callable run locally, exercising the
bytes-over-JSON encode/decode path end to end.
"""
from __future__ import annotations

import hashlib
import socket
import threading
import time

from deepview.offload.backends.remote import (
    RemoteWorkerBackend,
    serve,
    serve_once,
)
from deepview.offload.jobs import make_job
from deepview.offload.kdf import pbkdf2_sha256

_CALLABLE_REF = "deepview.offload.kdf:pbkdf2_sha256"


def _pick_free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def _start_worker(port: int) -> threading.Thread:
    t = threading.Thread(
        target=serve, args=("127.0.0.1", port), kwargs={"tls_context": None}, daemon=True
    )
    t.start()
    # Give the listener a moment to bind before clients connect.
    time.sleep(0.05)
    return t


def _pbkdf2_payload() -> dict[str, object]:
    return {
        "password": b"correct horse battery staple",
        "salt": b"\x01\x02\x03\x04\x05\x06\x07\x08",
        "iterations": 2048,
        "dklen": 32,
    }


def test_remote_backend_pbkdf2_roundtrip() -> None:
    port = _pick_free_port()
    _start_worker(port)

    backend = RemoteWorkerBackend(f"127.0.0.1:{port}")
    try:
        payload = _pbkdf2_payload()
        job = make_job("pbkdf2_sha256", payload, callable_ref=_CALLABLE_REF)
        result = backend.submit(job).result(timeout=10)

        assert result.ok, f"job failed: {result.error}"
        assert result.backend == "remote"
        assert result.job_id == job.job_id
        assert result.elapsed_s >= 0.0

        # Output must be bytes (hex-encoded over the wire, decoded by the client)
        # and equal to running the same callable locally.
        expected = pbkdf2_sha256(payload)
        assert isinstance(result.output, bytes)
        assert result.output == expected
        # Sanity: matches the underlying hashlib primitive too.
        assert result.output == hashlib.pbkdf2_hmac(
            "sha256",
            payload["password"],  # type: ignore[arg-type]
            payload["salt"],  # type: ignore[arg-type]
            2048,
            32,
        )
    finally:
        backend.shutdown()


def test_remote_backend_is_available_gated_on_endpoint() -> None:
    # Default engine behaviour must not change: an endpoint-less remote
    # backend reports unavailable so it never displaces ``process``.
    assert RemoteWorkerBackend("").is_available() is False
    assert RemoteWorkerBackend().is_available() is False
    # A malformed endpoint is also unavailable.
    assert RemoteWorkerBackend("not-a-host-port").is_available() is False
    # A well-formed endpoint flips availability on.
    assert RemoteWorkerBackend("127.0.0.1:9999").is_available() is True


def test_remote_backend_capabilities() -> None:
    caps = RemoteWorkerBackend("127.0.0.1:9999").capabilities()
    assert caps == {"remote", "pbkdf2_sha256", "argon2id", "sha512"}


def test_remote_backend_reports_error_on_missing_callable_ref() -> None:
    port = _pick_free_port()
    _start_worker(port)
    backend = RemoteWorkerBackend(f"127.0.0.1:{port}")
    try:
        job = make_job("noop", {})  # no callable_ref
        result = backend.submit(job).result(timeout=10)
        assert not result.ok
        assert result.error is not None
        assert "callable_ref" in result.error
    finally:
        backend.shutdown()


def test_remote_backend_reports_error_on_worker_exception() -> None:
    port = _pick_free_port()
    _start_worker(port)
    backend = RemoteWorkerBackend(f"127.0.0.1:{port}")
    try:
        # Missing 'iterations' key triggers KeyError inside the worker.
        job = make_job(
            "pbkdf2_sha256",
            {"password": b"x", "salt": b"y", "dklen": 16},
            callable_ref=_CALLABLE_REF,
        )
        result = backend.submit(job).result(timeout=10)
        assert not result.ok
        assert result.error is not None
        assert "KeyError" in result.error
    finally:
        backend.shutdown()


def test_remote_backend_connection_refused_fails_soft() -> None:
    # No worker listening: submit must resolve to ok=False, not raise.
    port = _pick_free_port()
    backend = RemoteWorkerBackend(f"127.0.0.1:{port}")
    try:
        job = make_job("pbkdf2_sha256", _pbkdf2_payload(), callable_ref=_CALLABLE_REF)
        result = backend.submit(job).result(timeout=10)
        assert not result.ok
        assert result.error is not None
        assert result.backend == "remote"
    finally:
        backend.shutdown()


def test_serve_once_single_connection() -> None:
    # Exercise serve_once directly over a connected socket pair.
    port = _pick_free_port()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def _accept_and_serve() -> None:
        conn, _ = srv.accept()
        with conn:
            serve_once(conn)

    t = threading.Thread(target=_accept_and_serve, daemon=True)
    t.start()
    time.sleep(0.05)

    backend = RemoteWorkerBackend(f"127.0.0.1:{port}")
    payload = _pbkdf2_payload()
    job = make_job("pbkdf2_sha256", payload, callable_ref=_CALLABLE_REF)
    result = backend.submit(job).result(timeout=10)
    t.join(timeout=5.0)
    srv.close()

    assert result.ok, f"job failed: {result.error}"
    assert result.output == pbkdf2_sha256(payload)
