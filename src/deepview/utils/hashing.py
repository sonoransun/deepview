"""Cryptographic hashing utilities for evidence integrity."""
from __future__ import annotations
import hashlib
from pathlib import Path

def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """Compute hash of a file, streaming to handle large files."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()

def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Compute hash of in-memory bytes."""
    return hashlib.new(algorithm, data).hexdigest()

def verify_hash(path: Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify a file's hash matches expected value."""
    return hash_file(path, algorithm) == expected_hash
