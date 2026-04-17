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
