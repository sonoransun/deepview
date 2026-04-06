"""Tests for the cryptographic hashing utilities."""
from __future__ import annotations

from pathlib import Path

from deepview.utils.hashing import hash_bytes, hash_file, verify_hash


class TestHashBytes:
    """Tests for hash_bytes()."""

    def test_hash_bytes_sha256(self):
        result = hash_bytes(b"hello", algorithm="sha256")
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hash_bytes_md5_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="not allowed"):
            hash_bytes(b"hello", algorithm="md5")


class TestHashFile:
    """Tests for hash_file()."""

    def test_hash_file(self, tmp_path: Path):
        p = tmp_path / "sample.bin"
        p.write_bytes(b"hello")
        assert hash_file(p) == hash_bytes(b"hello")

    def test_hash_file_sha512(self, tmp_path: Path):
        p = tmp_path / "sample.bin"
        p.write_bytes(b"hello")
        assert hash_file(p, algorithm="sha512") == hash_bytes(b"hello", algorithm="sha512")


class TestVerifyHash:
    """Tests for verify_hash()."""

    def test_verify_hash_correct(self, tmp_path: Path):
        p = tmp_path / "evidence.img"
        p.write_bytes(b"hello")
        expected = hash_bytes(b"hello")
        assert verify_hash(p, expected) is True

    def test_verify_hash_incorrect(self, tmp_path: Path):
        p = tmp_path / "evidence.img"
        p.write_bytes(b"hello")
        assert verify_hash(p, "0000000000000000000000000000000000000000000000000000000000000000") is False
