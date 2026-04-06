"""Cryptographic hashing utilities for evidence integrity."""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

# Only cryptographically strong algorithms allowed for forensic integrity.
ALLOWED_ALGORITHMS = frozenset({
    "sha256", "sha384", "sha512", "sha3_256", "sha3_512",
})


def _validate_algorithm(algorithm: str) -> None:
    """Reject weak or unknown hash algorithms."""
    if algorithm not in ALLOWED_ALGORITHMS:
        raise ValueError(
            f"Algorithm '{algorithm}' is not allowed for forensic use. "
            f"Permitted: {sorted(ALLOWED_ALGORITHMS)}"
        )


def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """Compute hash of a file, streaming to handle large files."""
    _validate_algorithm(algorithm)
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Compute hash of in-memory bytes."""
    _validate_algorithm(algorithm)
    return hashlib.new(algorithm, data).hexdigest()


def verify_hash(path: Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify a file's hash using constant-time comparison."""
    computed = hash_file(path, algorithm)
    return hmac.compare_digest(computed, expected_hash)
