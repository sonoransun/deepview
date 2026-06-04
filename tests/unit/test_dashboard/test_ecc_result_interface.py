"""Behaviour tests for the ECCResult dataclass invariants and helpers.

Lives under test_dashboard/ only because that is the directory this change's
lane owns; it exercises ``deepview.interfaces.ecc`` (a cross-cutting module),
not the dashboard.
"""
from __future__ import annotations

import pytest

from deepview.interfaces.ecc import ECCDecoder, ECCResult


class TestECCResultInvariants:
    def test_clean_decode_is_ok(self):
        r = ECCResult(data=b"abcd", errors_corrected=0, uncorrectable=False)
        assert r.ok is True

    def test_corrected_decode_is_ok(self):
        r = ECCResult(data=b"abcd", errors_corrected=3, uncorrectable=False)
        assert r.ok is True
        assert r.errors_corrected == 3

    def test_uncorrectable_is_not_ok(self):
        r = ECCResult(data=b"abcd", errors_corrected=0, uncorrectable=True)
        assert r.ok is False

    def test_negative_error_count_rejected(self):
        with pytest.raises(ValueError, match="errors_corrected must be >= 0"):
            ECCResult(data=b"", errors_corrected=-1, uncorrectable=False)

    def test_uncorrectable_with_corrections_rejected(self):
        # Contradictory: a codeword cannot be both uncorrectable and have had
        # errors corrected. base.ECCDataLayer only counts corrections on the
        # correctable branch, so this state would skew error_stats.
        with pytest.raises(ValueError, match="uncorrectable result cannot"):
            ECCResult(data=b"abcd", errors_corrected=2, uncorrectable=True)

    def test_result_is_frozen(self):
        r = ECCResult(data=b"abcd", errors_corrected=0, uncorrectable=False)
        with pytest.raises(Exception):
            r.errors_corrected = 5  # type: ignore[misc]


class TestECCDecoderDefaults:
    def test_encode_default_raises_not_implemented(self):
        class _Bare(ECCDecoder):
            name = "bare"
            data_chunk = 4
            ecc_bytes = 1

            def decode(self, data: bytes, ecc: bytes) -> ECCResult:
                return ECCResult(data=data, errors_corrected=0, uncorrectable=False)

        with pytest.raises(NotImplementedError, match="does not implement encode"):
            _Bare().encode(b"abcd")
