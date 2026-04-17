"""OpenCL GPU backend smoke test — skipped unless ``pyopencl`` imports.

We use ``pytest.importorskip`` so the whole file is skipped cleanly on
hosts without the ``offload_gpu`` extra installed or without an OpenCL
ICD loader. CI hosts lacking a GPU runtime therefore see this as
``skipped``, not ``failed``.

The asserted correctness reference is :func:`hashlib.pbkdf2_hmac`; the
GPU kernel must produce the exact same 32-byte output. If the kernel
compile fails on the target device the backend falls back to the CPU
implementation (which also uses :func:`hashlib.pbkdf2_hmac`), so the
bytes comparison still passes — we just expect the backend name to
indicate the fallback.
"""
from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("pyopencl")

from deepview.offload.backends.gpu_opencl import OpenCLBackend  # noqa: E402
from deepview.offload.jobs import make_job  # noqa: E402


@pytest.mark.skip(reason="GPU tests require a real OpenCL device; run explicitly")
def test_opencl_pbkdf2_known_answer() -> None:
    backend = OpenCLBackend()
    if not backend.is_available():
        pytest.skip("pyopencl imports but is_available() is False")

    expected = hashlib.pbkdf2_hmac("sha256", b"test", b"salt", 1000, 32)
    job = make_job(
        "pbkdf2_sha256",
        {"password": b"test", "salt": b"salt", "iterations": 1000, "dklen": 32},
    )
    future = backend.submit(job)
    result = future.result(timeout=60)
    assert result.ok, result.error
    assert result.backend in {"gpu-opencl", "gpu-opencl[cpu-fallback]"}
    assert result.output == expected
    backend.shutdown()


@pytest.mark.skip(reason="GPU tests require a real OpenCL device; run explicitly")
def test_opencl_argon2id_not_implemented() -> None:
    backend = OpenCLBackend()
    if not backend.is_available():
        pytest.skip("pyopencl imports but is_available() is False")
    job = make_job(
        "argon2id",
        {
            "password": b"x",
            "salt": b"0123456789abcdef",
            "time_cost": 1,
            "memory_cost": 8,
            "parallelism": 1,
            "dklen": 32,
        },
    )
    with pytest.raises(NotImplementedError):
        backend.submit(job)


def test_opencl_capabilities_when_available() -> None:
    backend = OpenCLBackend()
    caps = backend.capabilities()
    if backend.is_available():
        assert "pbkdf2_sha256_gpu" in caps
        assert "sha512_iter_gpu" in caps
    else:
        assert caps == set()
