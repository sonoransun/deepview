"""CUDA GPU backend smoke test — skipped unless ``pycuda`` imports.

Mirror of :mod:`test_gpu_opencl`. Requires both ``pycuda`` and a
working CUDA driver / runtime; ``pytest.importorskip`` catches the
missing package case, and the ``is_available()`` check catches the
"pycuda imports but driver init fails" case.
"""
from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("pycuda")

from deepview.offload.backends.gpu_cuda import CUDABackend  # noqa: E402
from deepview.offload.jobs import make_job  # noqa: E402


@pytest.mark.skip(reason="GPU tests require a real CUDA device; run explicitly")
def test_cuda_pbkdf2_known_answer() -> None:
    backend = CUDABackend()
    if not backend.is_available():
        pytest.skip("pycuda imports but is_available() is False")

    expected = hashlib.pbkdf2_hmac("sha256", b"test", b"salt", 1000, 32)
    job = make_job(
        "pbkdf2_sha256",
        {"password": b"test", "salt": b"salt", "iterations": 1000, "dklen": 32},
    )
    future = backend.submit(job)
    result = future.result(timeout=60)
    assert result.ok, result.error
    assert result.backend in {"gpu-cuda", "gpu-cuda[cpu-fallback]"}
    assert result.output == expected
    backend.shutdown()


@pytest.mark.skip(reason="GPU tests require a real CUDA device; run explicitly")
def test_cuda_argon2id_not_implemented() -> None:
    backend = CUDABackend()
    if not backend.is_available():
        pytest.skip("pycuda imports but is_available() is False")
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


def test_cuda_capabilities_when_available() -> None:
    backend = CUDABackend()
    caps = backend.capabilities()
    if backend.is_available():
        assert "pbkdf2_sha256_gpu" in caps
        assert "sha512_iter_gpu" in caps
    else:
        assert caps == set()
