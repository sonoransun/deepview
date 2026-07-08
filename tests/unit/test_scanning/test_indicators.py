"""Tests for the IoC indicator matching engine (content-hash correctness)."""
from __future__ import annotations

import hashlib

from deepview.scanning.indicators import IndicatorEngine, Indicator


def _engine(*indicators):
    eng = IndicatorEngine()
    for ind in indicators:
        eng.add_indicator(ind)
    return eng


class TestContentHashMatching:
    def test_sha256_matches_by_content(self):
        digest = hashlib.sha256(b"EVIL").hexdigest()
        eng = _engine(Indicator(ioc_type="hash_sha256", value=digest))
        matches = eng.scan_bytes(b"EVIL")
        assert len(matches) == 1
        assert matches[0].found_at == "content_hash"

    def test_md5_matches_by_content(self):
        digest = hashlib.md5(b"BAD").hexdigest()  # noqa: S324 - matching known-bad hash
        eng = _engine(Indicator(ioc_type="hash_md5", value=digest))
        assert len(eng.scan_bytes(b"BAD")) == 1

    def test_no_false_positive_when_digest_text_present(self):
        """The old bug matched when the hex digest string appeared in the bytes."""
        digest = hashlib.sha256(b"EVIL").hexdigest()
        eng = _engine(Indicator(ioc_type="hash_sha256", value=digest))
        # The bytes literally contain the digest string, but their content hash
        # is different -> must NOT match.
        assert eng.scan_bytes(digest.encode()) == []

    def test_no_match_for_different_content(self):
        digest = hashlib.sha256(b"EVIL").hexdigest()
        eng = _engine(Indicator(ioc_type="hash_sha256", value=digest))
        assert eng.scan_bytes(b"benign") == []


class TestStringMatching:
    def test_string_indicator_offset(self):
        eng = _engine(Indicator(ioc_type="string", value="mutex-name"))
        matches = eng.scan_bytes(b"....mutex-name....")
        assert len(matches) == 1
        assert matches[0].offset == 4
