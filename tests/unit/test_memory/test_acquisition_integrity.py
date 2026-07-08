"""Tests for acquisition provenance, hashing, and truncation semantics."""
from __future__ import annotations

import builtins
import hashlib
import json
import time

from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.base import make_result
from deepview.memory.acquisition.live import LiveMemoryProvider


class TestMakeResult:
    def test_records_provenance_and_manifest(self, tmp_path):
        img = tmp_path / "mem.raw"
        img.write_bytes(b"MEMORY-IMAGE-BYTES")
        result = make_result(img, DumpFormat.RAW, time.time() - 1.0, method="unit")

        assert result.success is True
        assert result.truncated is False
        assert result.algorithm == "sha256"
        assert result.hash_sha256 == hashlib.sha256(b"MEMORY-IMAGE-BYTES").hexdigest()
        assert result.tool_version  # non-empty
        assert result.acquired_at  # ISO timestamp

        assert result.manifest_path is not None and result.manifest_path.exists()
        data = json.loads(result.manifest_path.read_text())
        art = data["artifacts"][0]
        assert art["digest"] == result.hash_sha256
        assert art["source_method"] == "unit"
        assert art["truncated"] is False

    def test_truncated_recorded_in_result_and_manifest(self, tmp_path):
        img = tmp_path / "mem.raw"
        img.write_bytes(b"partial")
        result = make_result(
            img, DumpFormat.RAW, time.time(), truncated=True, read_error="hole at 0x1000"
        )
        assert result.truncated is True
        data = json.loads(result.manifest_path.read_text())
        assert data["artifacts"][0]["truncated"] is True
        assert "hole" in data["artifacts"][0]["read_error"]

    def test_no_manifest_when_disabled(self, tmp_path):
        img = tmp_path / "mem.raw"
        img.write_bytes(b"data")
        result = make_result(img, DumpFormat.RAW, time.time(), write_manifest=False)
        assert result.manifest_path is None
        assert not (tmp_path / "mem.raw.manifest.json").exists()


class TestLiveTruncation:
    def test_read_error_marks_truncated(self, tmp_path, monkeypatch):
        """A mid-stream read error must truncate and record, not silently succeed."""
        provider = LiveMemoryProvider()
        monkeypatch.setattr(provider, "_find_source", lambda: "/fake/kcore")

        class FakeSource:
            def __init__(self):
                self.reads = 0

            def read(self, size):
                self.reads += 1
                if self.reads == 1:
                    return b"A" * 16
                raise OSError("simulated reserved-region hole")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        real_open = builtins.open

        def fake_open(path, mode="r", *args, **kwargs):
            if path == "/fake/kcore":
                return FakeSource()
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", fake_open)

        out = tmp_path / "live.raw"
        result = provider.acquire(AcquisitionTarget(), out, DumpFormat.RAW)

        assert result.truncated is True
        assert "simulated reserved-region hole" in result.read_error
        # Only the successfully-read bytes were written.
        assert out.read_bytes() == b"A" * 16
        # The digest is over exactly what was captured.
        assert result.hash_sha256 == hashlib.sha256(b"A" * 16).hexdigest()

    def test_clean_eof_not_truncated(self, tmp_path, monkeypatch):
        provider = LiveMemoryProvider()
        monkeypatch.setattr(provider, "_find_source", lambda: "/fake/kcore")

        class CleanSource:
            def __init__(self):
                self.done = False

            def read(self, size):
                if self.done:
                    return b""
                self.done = True
                return b"COMPLETE"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        real_open = builtins.open

        def fake_open(path, mode="r", *args, **kwargs):
            if path == "/fake/kcore":
                return CleanSource()
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", fake_open)

        out = tmp_path / "live.raw"
        result = provider.acquire(AcquisitionTarget(), out, DumpFormat.RAW)
        assert result.truncated is False
        assert out.read_bytes() == b"COMPLETE"
