"""Tests for :class:`Passphrase.derive` + OffloadEngine interaction."""
from __future__ import annotations

import asyncio
from concurrent.futures import Future
from typing import Any

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.events import ContainerUnlockProgressEvent
from deepview.offload.futures import OffloadFuture
from deepview.offload.jobs import OffloadJob, OffloadResult
from deepview.storage.containers.unlock import ContainerHeader, Passphrase


class _StubEngine:
    """Stand-in for :class:`OffloadEngine` that resolves jobs synchronously."""

    def __init__(self, context: AnalysisContext, result: OffloadResult) -> None:
        self.context = context
        self._result = result
        self.submitted: list[OffloadJob] = []

    def submit(self, job: OffloadJob) -> OffloadFuture[Any]:
        self.submitted.append(job)
        stdlib: Future[OffloadResult] = Future()
        # Return the canned result regardless of input.
        stdlib.set_result(
            OffloadResult(
                job_id=job.job_id,
                ok=self._result.ok,
                output=self._result.output,
                error=self._result.error,
                elapsed_s=self._result.elapsed_s,
                backend=self._result.backend,
            )
        )
        return OffloadFuture(stdlib, job.job_id)


def test_passphrase_derive_submits_pbkdf2_and_returns_result() -> None:
    ctx = AnalysisContext.for_testing()
    derived = b"derived_key_xxxxxxxxxxxxxxxxxxxx"  # 32 bytes
    assert len(derived) == 32
    engine = _StubEngine(
        ctx,
        OffloadResult(
            job_id="placeholder",
            ok=True,
            output=derived,
            error=None,
            elapsed_s=0.01,
            backend="stub",
        ),
    )

    progress: list[ContainerUnlockProgressEvent] = []
    ctx.events.subscribe(
        ContainerUnlockProgressEvent, lambda e: progress.append(e)
    )

    header = ContainerHeader(
        format="luks",
        cipher="aes-xts-plain64",
        sector_size=512,
        data_offset=4096,
        data_length=1 << 20,
        kdf="pbkdf2",
        kdf_params={"salt": b"NaCl", "iterations": 1000, "dklen": 32},
        raw=b"",
    )

    out = asyncio.run(Passphrase(passphrase="swordfish").derive(engine, header))  # type: ignore[arg-type]
    assert out == derived

    # Submitted exactly one job with the expected callable_ref + payload.
    assert len(engine.submitted) == 1
    job = engine.submitted[0]
    assert job.callable_ref == "deepview.offload.kdf:pbkdf2_sha256"
    payload = job.payload
    assert isinstance(payload, dict)
    assert payload["password"] == "swordfish"
    assert payload["salt"] == b"NaCl"
    assert payload["iterations"] == 1000
    assert payload["dklen"] == 32

    # Progress event was published.
    assert len(progress) == 1
    assert progress[0].format == "luks"
    assert progress[0].stage == "kdf"
    assert progress[0].attempted == 1
    assert progress[0].total == 1


def test_passphrase_derive_selects_argon2_for_argon2id_header() -> None:
    ctx = AnalysisContext.for_testing()
    engine = _StubEngine(
        ctx,
        OffloadResult(
            job_id="p",
            ok=True,
            output=b"x" * 32,
            error=None,
            elapsed_s=0.0,
            backend="stub",
        ),
    )
    header = ContainerHeader(
        format="luks2",
        cipher="aes-xts-plain64",
        sector_size=512,
        data_offset=4096,
        data_length=1 << 20,
        kdf="argon2id",
        kdf_params={"salt": b"salty", "iterations": 3, "dklen": 32},
        raw=b"",
    )
    _ = asyncio.run(Passphrase(passphrase="pw").derive(engine, header))  # type: ignore[arg-type]
    assert engine.submitted[0].callable_ref == "deepview.offload.kdf:argon2id"


def test_passphrase_derive_raises_on_failed_job() -> None:
    ctx = AnalysisContext.for_testing()
    engine = _StubEngine(
        ctx,
        OffloadResult(
            job_id="p",
            ok=False,
            output=None,
            error="boom",
            elapsed_s=0.0,
            backend="stub",
        ),
    )
    header = ContainerHeader(
        format="luks",
        cipher="aes-xts-plain64",
        sector_size=512,
        data_offset=4096,
        data_length=1 << 20,
        kdf="pbkdf2",
        kdf_params={"salt": b"x", "iterations": 10, "dklen": 32},
        raw=b"",
    )
    with pytest.raises(RuntimeError, match="KDF offload failed"):
        asyncio.run(Passphrase(passphrase="pw").derive(engine, header))  # type: ignore[arg-type]
