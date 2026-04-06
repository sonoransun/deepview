"""Security tests for cryptographic hashing utilities."""
from __future__ import annotations

import pytest

from deepview.utils.hashing import hash_file, hash_bytes, verify_hash, ALLOWED_ALGORITHMS


class TestAlgorithmWhitelist:
    def test_sha256_allowed(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        hash_file(f, "sha256")  # Should not raise

    def test_sha512_allowed(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        hash_file(f, "sha512")  # Should not raise

    def test_md5_rejected(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        with pytest.raises(ValueError, match="not allowed"):
            hash_file(f, "md5")

    def test_sha1_rejected(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        with pytest.raises(ValueError, match="not allowed"):
            hash_file(f, "sha1")

    def test_unknown_algorithm_rejected(self):
        with pytest.raises(ValueError, match="not allowed"):
            hash_bytes(b"data", "md4")

    def test_empty_algorithm_rejected(self):
        with pytest.raises(ValueError, match="not allowed"):
            hash_bytes(b"data", "")

    def test_allowed_algorithms_are_strong(self):
        for alg in ALLOWED_ALGORITHMS:
            assert "md5" not in alg
            assert "sha1" not in alg or "sha1" != alg


class TestTimingSafeComparison:
    def test_verify_correct_hash(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"known content")
        h = hash_file(f)
        assert verify_hash(f, h) is True

    def test_verify_incorrect_hash(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"known content")
        assert verify_hash(f, "0" * 64) is False

    def test_verify_empty_expected(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        assert verify_hash(f, "") is False


class TestEdgeCases:
    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = hash_file(f)
        assert len(result) == 64  # SHA-256 hex length

    def test_nonexistent_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            hash_file(tmp_path / "nonexistent.bin")

    def test_hash_bytes_empty(self):
        result = hash_bytes(b"")
        assert len(result) == 64
