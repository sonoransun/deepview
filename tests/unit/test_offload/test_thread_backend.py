"""Thread-pool backend round-trip test."""
from __future__ import annotations

import hashlib

from deepview.offload.backends.thread import ThreadPoolBackend
from deepview.offload.jobs import make_job


def test_thread_backend_pbkdf2_roundtrip() -> None:
    backend = ThreadPoolBackend(max_workers=2)
    try:
        payload = {
            "password": b"correct horse battery staple",
            "salt": b"\x01\x02\x03\x04",
            "iterations": 2048,
            "dklen": 32,
        }
        job = make_job(
            "pbkdf2_sha256",
            payload,
            callable_ref="deepview.offload.kdf:pbkdf2_sha256",
        )
        future = backend.submit(job)
        result = future.result(timeout=10)
        assert result.ok, f"job failed: {result.error}"
        assert result.backend == "thread"
        expected = hashlib.pbkdf2_hmac("sha256", payload["password"], payload["salt"], 2048, 32)
        assert result.output == expected
        assert result.elapsed_s >= 0.0
    finally:
        backend.shutdown(wait=True)


def test_thread_backend_reports_error_on_missing_callable_ref() -> None:
    backend = ThreadPoolBackend(max_workers=1)
    try:
        job = make_job("noop", {})
        result = backend.submit(job).result(timeout=5)
        assert not result.ok
        assert result.error is not None
        assert "callable_ref" in result.error
    finally:
        backend.shutdown(wait=True)


def test_thread_backend_reports_error_on_worker_exception() -> None:
    backend = ThreadPoolBackend(max_workers=1)
    try:
        # Missing 'iterations' key triggers KeyError inside the worker.
        job = make_job(
            "pbkdf2_sha256",
            {"password": b"x", "salt": b"y", "dklen": 16},
            callable_ref="deepview.offload.kdf:pbkdf2_sha256",
        )
        result = backend.submit(job).result(timeout=5)
        assert not result.ok
        assert result.error is not None
        assert "KeyError" in result.error
    finally:
        backend.shutdown(wait=True)
