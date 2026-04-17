"""Top-level KDF dispatch functions usable as ``callable_ref``.

Every function here accepts a single ``dict`` *payload*, does exactly
one piece of work, and returns ``bytes``. The shape keeps
:class:`~deepview.offload.jobs.OffloadJob` payloads pickle-safe for
the process-pool backend and wire-safe for the future remote backend.

When a function needs an optional third-party library (only
``argon2-cffi`` today) it is imported lazily inside the function body
— a core install with no offload extras still loads this module
without ImportError.
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — annotation-only
    from collections.abc import Mapping


def _require_bytes(value: Any, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"payload field {field!r} must be bytes or str, got {type(value).__name__}")


def pbkdf2_sha256(payload: Mapping[str, Any]) -> bytes:
    """PBKDF2-HMAC-SHA256.

    Payload
    -------
    ``password`` : ``bytes`` | ``str``
    ``salt`` : ``bytes``
    ``iterations`` : ``int``
    ``dklen`` : ``int``
    """
    password = _require_bytes(payload["password"], "password")
    salt = _require_bytes(payload["salt"], "salt")
    iterations = int(payload["iterations"])
    dklen = int(payload["dklen"])
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if dklen <= 0:
        raise ValueError("dklen must be positive")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def argon2id(payload: Mapping[str, Any]) -> bytes:
    """Argon2id via ``argon2-cffi``'s low-level hash_secret_raw.

    Payload
    -------
    ``password``, ``salt`` : ``bytes`` | ``str``
    ``time_cost``, ``memory_cost``, ``parallelism``, ``dklen`` : ``int``

    Lazy-imports ``argon2``; raises :class:`ImportError` with a clear
    message when the optional dep is missing so the caller can fall
    back to a slower path.
    """
    try:
        from argon2 import low_level as _argon2_low
    except ImportError as exc:
        raise ImportError(
            "argon2id offload requires the 'argon2-cffi' package "
            "(install the 'containers' extra: pip install 'deepview[containers]')"
        ) from exc

    password = _require_bytes(payload["password"], "password")
    salt = _require_bytes(payload["salt"], "salt")
    time_cost = int(payload["time_cost"])
    memory_cost = int(payload["memory_cost"])
    parallelism = int(payload["parallelism"])
    dklen = int(payload["dklen"])
    return _argon2_low.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=dklen,
        type=_argon2_low.Type.ID,
    )


def sha512_iter(payload: Mapping[str, Any]) -> bytes:
    """Repeated SHA-512 digest of ``data`` for *iterations* rounds.

    Payload
    -------
    ``data`` : ``bytes`` | ``str``
    ``iterations`` : ``int``

    Returns the final 64-byte digest. Used by VeraCrypt / TrueCrypt
    PRF variants and by the offload benchmark harness.
    """
    data = _require_bytes(payload["data"], "data")
    iterations = int(payload["iterations"])
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    digest = data
    for _ in range(iterations):
        digest = hashlib.sha512(digest).digest()
    return digest


__all__ = ["pbkdf2_sha256", "argon2id", "sha512_iter"]
