"""GPU backend fallback behavior when optional deps are missing.

These tests don't require a GPU — they exercise the "no pyopencl / no
pycuda installed" branch of :class:`OpenCLBackend` / :class:`CUDABackend`.
On a host where the optional package *is* installed we force the
import to fail via a ``builtins.__import__`` monkeypatch so the test
is deterministic regardless of the runtime environment.
"""
from __future__ import annotations

import builtins
from collections.abc import Iterator
from typing import Any

import pytest

from deepview.offload.backends.gpu_cuda import CUDABackend
from deepview.offload.backends.gpu_opencl import OpenCLBackend
from deepview.offload.jobs import make_job


@pytest.fixture
def block_gpu_imports(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force ``import pyopencl`` and ``import pycuda*`` to raise.

    Strips any already-cached entries from ``sys.modules`` so the
    backend's lazy ``import`` inside ``__init__`` re-enters the
    ``__import__`` hook rather than hitting the cache.
    """
    import sys

    blocked = ("pyopencl", "pycuda")
    for mod_name in list(sys.modules):
        if any(mod_name == b or mod_name.startswith(b + ".") for b in blocked):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if any(name == b or name.startswith(b + ".") for b in blocked):
            raise ImportError(f"{name} blocked for test")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    yield


def test_opencl_backend_unavailable_without_pyopencl(
    block_gpu_imports: None,
) -> None:
    backend = OpenCLBackend()
    assert backend.is_available() is False
    assert backend.capabilities() == set()
    # Name is still exposed for engine introspection.
    assert backend.name == "gpu-opencl"
    job = make_job(
        "pbkdf2_sha256",
        {"password": b"x", "salt": b"s", "iterations": 10, "dklen": 32},
    )
    with pytest.raises(NotImplementedError):
        backend.submit(job)


def test_cuda_backend_unavailable_without_pycuda(
    block_gpu_imports: None,
) -> None:
    backend = CUDABackend()
    assert backend.is_available() is False
    assert backend.capabilities() == set()
    assert backend.name == "gpu-cuda"
    job = make_job(
        "pbkdf2_sha256",
        {"password": b"x", "salt": b"s", "iterations": 10, "dklen": 32},
    )
    with pytest.raises(NotImplementedError):
        backend.submit(job)


def test_opencl_shutdown_safe_when_unavailable(block_gpu_imports: None) -> None:
    backend = OpenCLBackend()
    # shutdown() must not raise even when no device context was ever set up.
    backend.shutdown(wait=True)
    backend.shutdown(wait=False)


def test_cuda_shutdown_safe_when_unavailable(block_gpu_imports: None) -> None:
    backend = CUDABackend()
    backend.shutdown(wait=True)
    backend.shutdown(wait=False)
