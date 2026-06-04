"""Unit tests for :mod:`deepview.offload.kdf`.

The module's three dispatch functions (``pbkdf2_sha256``, ``argon2id``,
``sha512_iter``) each take a single ``Mapping[str, Any]`` payload and
return ``bytes``. These tests verify the validation rules actually
present in the module — we do not assert on rules the code does not
enforce.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# Make the shared test helper importable.
_TESTS_ROOT = Path(__file__).resolve().parents[2]
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))

from deepview.offload.kdf import argon2id, pbkdf2_sha256, sha512_iter  # noqa: E402


# ---------------------------------------------------------------------------
# pbkdf2_sha256
# ---------------------------------------------------------------------------


def test_pbkdf2_valid_call_matches_hashlib() -> None:
    """Happy path: output matches the stdlib reference."""
    payload = {
        "password": "hunter2",
        "salt": b"NaCl",
        "iterations": 100,
        "dklen": 32,
    }
    got = pbkdf2_sha256(payload)
    expected = hashlib.pbkdf2_hmac("sha256", b"hunter2", b"NaCl", 100, 32)
    assert got == expected
    assert len(got) == 32


def test_pbkdf2_accepts_bytes_password() -> None:
    payload = {
        "password": b"hunter2",
        "salt": b"NaCl",
        "iterations": 50,
        "dklen": 16,
    }
    got = pbkdf2_sha256(payload)
    assert len(got) == 16


def test_pbkdf2_zero_iterations_raises_value_error() -> None:
    payload = {
        "password": "pw",
        "salt": b"salt",
        "iterations": 0,
        "dklen": 32,
    }
    with pytest.raises(ValueError, match="iterations must be positive"):
        pbkdf2_sha256(payload)


def test_pbkdf2_negative_iterations_raises_value_error() -> None:
    payload = {
        "password": "pw",
        "salt": b"salt",
        "iterations": -1,
        "dklen": 32,
    }
    with pytest.raises(ValueError, match="iterations must be positive"):
        pbkdf2_sha256(payload)


def test_pbkdf2_zero_dklen_raises_value_error() -> None:
    payload = {
        "password": "pw",
        "salt": b"salt",
        "iterations": 10,
        "dklen": 0,
    }
    with pytest.raises(ValueError, match="dklen must be positive"):
        pbkdf2_sha256(payload)


def test_pbkdf2_non_bytes_non_str_salt_raises_type_error() -> None:
    """_require_bytes only accepts bytes or str; int should raise TypeError."""
    payload = {
        "password": "pw",
        "salt": 12345,  # not bytes/str
        "iterations": 10,
        "dklen": 32,
    }
    with pytest.raises(TypeError, match="salt"):
        pbkdf2_sha256(payload)


def test_pbkdf2_large_dklen_accepted() -> None:
    """Module does not cap dklen; a 512-byte request succeeds."""
    payload = {
        "password": "pw",
        "salt": b"salt",
        "iterations": 10,
        "dklen": 512,
    }
    got = pbkdf2_sha256(payload)
    assert len(got) == 512


def test_pbkdf2_str_salt_coerced_to_bytes() -> None:
    """Contrary to the docstring, _require_bytes also accepts str salts."""
    payload = {
        "password": "pw",
        "salt": "saltstr",
        "iterations": 10,
        "dklen": 16,
    }
    got = pbkdf2_sha256(payload)
    expected = hashlib.pbkdf2_hmac("sha256", b"pw", b"saltstr", 10, 16)
    assert got == expected


# ---------------------------------------------------------------------------
# sha512_iter (stdlib-only, good smoke test for the validation rules)
# ---------------------------------------------------------------------------


def test_sha512_iter_single_round_equals_plain_sha512() -> None:
    got = sha512_iter({"data": b"abc", "iterations": 1})
    assert got == hashlib.sha512(b"abc").digest()
    assert len(got) == 64


def test_sha512_iter_multiple_rounds() -> None:
    got = sha512_iter({"data": b"abc", "iterations": 3})
    expected = b"abc"
    for _ in range(3):
        expected = hashlib.sha512(expected).digest()
    assert got == expected


def test_sha512_iter_zero_iterations_raises() -> None:
    with pytest.raises(ValueError, match="iterations must be positive"):
        sha512_iter({"data": b"abc", "iterations": 0})


def test_sha512_iter_negative_iterations_raises() -> None:
    with pytest.raises(ValueError, match="iterations must be positive"):
        sha512_iter({"data": b"abc", "iterations": -5})


# ---------------------------------------------------------------------------
# argon2id (optional dep)
# ---------------------------------------------------------------------------


def test_argon2id_valid_call_returns_dklen_bytes() -> None:
    pytest.importorskip("argon2")
    payload = {
        "password": "hunter2",
        "salt": b"salt____salt____",  # 16 bytes min recommended
        "time_cost": 1,
        "memory_cost": 8,
        "parallelism": 1,
        "dklen": 32,
    }
    got = argon2id(payload)
    assert isinstance(got, bytes)
    assert len(got) == 32


def test_argon2id_determinism() -> None:
    """Same inputs produce the same output."""
    pytest.importorskip("argon2")
    payload = {
        "password": b"pw",
        "salt": b"salt____salt____",
        "time_cost": 1,
        "memory_cost": 8,
        "parallelism": 1,
        "dklen": 32,
    }
    a = argon2id(payload)
    b = argon2id(payload)
    assert a == b


def test_argon2id_known_answer_fixed_vector() -> None:
    """Pin the raw Argon2id output for fixed params — catches any regression
    in how the offload wrapper maps parameters onto argon2-cffi.

    (argon2-cffi's hash_secret_raw exposes neither the secret-key nor the
    associated-data inputs the literal RFC 9106 vector uses, so this is a
    fixed known-answer computed from the reference implementation rather than
    the RFC vector itself.)
    """
    pytest.importorskip("argon2")
    payload = {
        "password": b"deepview-kat-password",
        "salt": b"0123456789abcdef",
        "time_cost": 3,
        "memory_cost": 256,
        "parallelism": 2,
        "dklen": 32,
    }
    expected = bytes.fromhex(
        "cf298c2e50107e0de735259c112fc5ff67ed0b1c0a15b7ffe5b47cfd547e8421"
    )
    assert argon2id(payload) == expected


def test_argon2id_matches_reference_low_level() -> None:
    """The offload wrapper is a faithful pass-through to argon2-cffi's
    Type.ID hash_secret_raw (same params -> same bytes)."""
    pytest.importorskip("argon2")
    from argon2 import low_level

    password, salt = b"pass-through", b"sixteen-byte-slt"
    payload = {
        "password": password,
        "salt": salt,
        "time_cost": 2,
        "memory_cost": 128,
        "parallelism": 1,
        "dklen": 32,
    }
    ref = low_level.hash_secret_raw(
        secret=password, salt=salt, time_cost=2, memory_cost=128,
        parallelism=1, hash_len=32, type=low_level.Type.ID,
    )
    assert argon2id(payload) == ref


def test_argon2id_runs_through_offload_engine() -> None:
    """End-to-end: an Argon2id job dispatched through the real OffloadEngine
    (the path container unlock uses) returns the same key as a direct call,
    and records which backend executed it."""
    pytest.importorskip("argon2")
    from deepview.core.context import AnalysisContext
    from deepview.offload.jobs import make_job

    ctx = AnalysisContext.for_testing()
    payload = {
        "password": b"engine-pw",
        "salt": b"sixteen-byte-slt",
        "time_cost": 2,
        "memory_cost": 64,
        "parallelism": 1,
        "dklen": 32,
    }
    job = make_job("argon2id", payload, callable_ref="deepview.offload.kdf:argon2id")
    result = ctx.offload.submit(job).await_result(timeout=60.0)
    assert result.ok, result.error
    assert result.output == argon2id(payload)
    assert result.backend in ("process", "thread")
