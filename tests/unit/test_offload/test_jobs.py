"""Smoke tests for :mod:`deepview.offload.jobs`."""
from __future__ import annotations

from deepview.offload.jobs import OffloadJob, make_job


def test_make_job_assigns_unique_ids() -> None:
    j1 = make_job("pbkdf2_sha256", {"a": 1})
    j2 = make_job("pbkdf2_sha256", {"a": 1})
    assert j1.job_id != j2.job_id
    assert len(j1.job_id) == 32  # uuid4().hex


def test_make_job_fields_default() -> None:
    j = make_job("sha512", {"data": b"x", "iterations": 1})
    assert j.kind == "sha512"
    assert j.callable_ref is None
    assert j.cost_hint == 1
    assert j.deadline_s is None


def test_offload_job_equality_by_id() -> None:
    j1 = OffloadJob(job_id="fixed", kind="k", payload={})
    j2 = OffloadJob(job_id="fixed", kind="other", payload={"different": True})
    j3 = OffloadJob(job_id="other", kind="k", payload={})
    assert j1 == j2
    assert j1 != j3
    assert hash(j1) == hash(j2)
    assert j1 != object()
