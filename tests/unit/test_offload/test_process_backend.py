"""Process-pool backend round-trip test."""
from __future__ import annotations

import hashlib

from deepview.offload.backends.process import ProcessPoolBackend
from deepview.offload.jobs import make_job


def test_process_backend_pbkdf2_parallel_batch() -> None:
    backend = ProcessPoolBackend(max_workers=2)
    try:
        reference = []
        jobs = []
        for i in range(4):
            password = f"pw-{i}".encode()
            salt = f"salt-{i}".encode().ljust(8, b"\x00")
            reference.append(hashlib.pbkdf2_hmac("sha256", password, salt, 1024, 32))
            jobs.append(
                make_job(
                    "pbkdf2_sha256",
                    {
                        "password": password,
                        "salt": salt,
                        "iterations": 1024,
                        "dklen": 32,
                    },
                    callable_ref="deepview.offload.kdf:pbkdf2_sha256",
                )
            )

        futures = [backend.submit(j) for j in jobs]
        results = [f.result(timeout=30) for f in futures]

        assert all(r.ok for r in results), [r.error for r in results if not r.ok]
        assert all(r.backend == "process" for r in results)
        assert [r.output for r in results] == reference
    finally:
        backend.shutdown(wait=True)
