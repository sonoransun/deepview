"""Tests for the macOS WKdm page decompressor stub.

The full WKdm bit-stream decoder is intentionally unimplemented (see the
module docstring); these tests pin down the *input validation* contract that
sits in front of the stub: a structurally impossible header must surface a
``ValueError`` rather than a misleading ``NotImplementedError``, while a
well-formed header still raises ``NotImplementedError`` so callers fall back
gracefully.
"""
from __future__ import annotations

import pytest

from deepview.storage.encodings.wkdm import WKDM_PAGE_SIZE, decompress_wkdm


def _header(*section_ends: int, total_words: int = 16) -> bytes:
    """Build a WKdm compressed buffer of *total_words* whose first four words
    are the given section end-offsets (little-endian u32)."""
    assert total_words >= 4
    buf = bytearray(total_words * 4)
    for i, end in enumerate(section_ends):
        buf[i * 4:i * 4 + 4] = end.to_bytes(4, "little")
    return bytes(buf)


class TestDecompressWkdmValidation:
    def test_wrong_page_size_rejected(self) -> None:
        with pytest.raises(ValueError, match="4096-byte pages"):
            decompress_wkdm(b"\x00" * 64, expected_size=8192)

    def test_short_stream_rejected(self) -> None:
        with pytest.raises(ValueError, match="16-byte header"):
            decompress_wkdm(b"\x00" * 8)

    def test_well_formed_header_raises_not_implemented(self) -> None:
        buf = _header(5, 8, 10, 12, total_words=16)
        with pytest.raises(NotImplementedError, match="WKdm decoder stub"):
            decompress_wkdm(buf)

    def test_monotonic_equal_offsets_allowed(self) -> None:
        # Equal (non-decreasing) section ends describe empty sections — still
        # structurally valid, so the stub error (not ValueError) wins.
        buf = _header(4, 4, 4, 4, total_words=16)
        with pytest.raises(NotImplementedError):
            decompress_wkdm(buf)

    def test_non_monotonic_header_rejected(self) -> None:
        buf = _header(10, 5, 12, 12, total_words=16)
        with pytest.raises(ValueError, match="non-decreasing"):
            decompress_wkdm(buf)

    def test_section_end_inside_header_rejected(self) -> None:
        # A section that ends before word 4 would overlap the 4-word header.
        buf = _header(2, 8, 10, 12, total_words=16)
        with pytest.raises(ValueError, match="non-decreasing"):
            decompress_wkdm(buf)

    def test_section_end_past_buffer_rejected(self) -> None:
        buf = _header(5, 8, 10, 999, total_words=16)
        with pytest.raises(ValueError, match="exceeds"):
            decompress_wkdm(buf)

    def test_section_end_exactly_at_buffer_end_allowed(self) -> None:
        # An offset equal to the buffer's word count is in-bounds.
        buf = _header(4, 8, 12, 16, total_words=16)
        with pytest.raises(NotImplementedError):
            decompress_wkdm(buf)

    def test_page_size_constant(self) -> None:
        assert WKDM_PAGE_SIZE == 4096
