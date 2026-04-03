"""Tests for multi-encoding string carver."""
from __future__ import annotations

import os

import pytest

from deepview.scanning.string_carver import CarvedString, StringCarver


class TestShannonEntropy:
    def test_zero_entropy(self):
        # All same byte → 0 bits/byte
        assert StringCarver.shannon_entropy(b"\x00" * 100) == 0.0

    def test_max_entropy(self):
        # All 256 byte values equally → ~8 bits/byte
        data = bytes(range(256)) * 4
        entropy = StringCarver.shannon_entropy(data)
        assert 7.9 < entropy <= 8.0

    def test_moderate_entropy(self):
        data = b"Hello, World! This is a test string."
        entropy = StringCarver.shannon_entropy(data)
        assert 2.0 < entropy < 5.0

    def test_empty(self):
        assert StringCarver.shannon_entropy(b"") == 0.0


class TestStringCarverASCII:
    def test_simple_ascii(self):
        carver = StringCarver(encodings=["ascii"], min_length=4)
        data = b"\x00\x00Hello World\x00\x00"
        strings = list(carver.carve(data))
        assert len(strings) == 1
        assert strings[0].value == "Hello World"
        assert strings[0].encoding == "ascii"
        assert strings[0].offset == 2

    def test_multiple_strings(self):
        carver = StringCarver(encodings=["ascii"], min_length=4)
        data = b"\x00ABCD\x00\x00EFGH\x00"
        strings = list(carver.carve(data))
        assert len(strings) == 2
        assert strings[0].value == "ABCD"
        assert strings[1].value == "EFGH"

    def test_min_length_filter(self):
        carver = StringCarver(encodings=["ascii"], min_length=6)
        data = b"\x00Hi\x00Hello World\x00"
        strings = list(carver.carve(data))
        assert len(strings) == 1
        assert strings[0].value == "Hello World"

    def test_base_offset(self):
        carver = StringCarver(encodings=["ascii"], min_length=4)
        data = b"\x00\x00Test\x00"
        strings = list(carver.carve(data, base_offset=0x1000))
        assert strings[0].offset == 0x1002

    def test_no_strings(self):
        carver = StringCarver(encodings=["ascii"], min_length=4)
        data = b"\x00\x01\x02\x03\x04\x05"
        strings = list(carver.carve(data))
        assert len(strings) == 0


class TestStringCarverUTF16:
    def test_utf16le(self):
        carver = StringCarver(encodings=["utf-16-le"], min_length=4)
        text = "Hello"
        encoded = text.encode("utf-16-le")
        data = b"\x00\x00" + encoded + b"\x00\x00"
        strings = list(carver.carve(data))
        assert len(strings) == 1
        assert strings[0].value == "Hello"
        assert strings[0].encoding == "utf-16-le"

    def test_utf16be(self):
        carver = StringCarver(encodings=["utf-16-be"], min_length=4)
        text = "Test"
        encoded = text.encode("utf-16-be")
        data = b"\x00\x00" + encoded + b"\x00\x00"
        strings = list(carver.carve(data))
        assert len(strings) == 1
        assert strings[0].value == "Test"

    def test_windows_style_path(self):
        carver = StringCarver(encodings=["utf-16-le"], min_length=4)
        text = r"C:\Windows\System32"
        encoded = text.encode("utf-16-le")
        data = b"\x00\x00" + encoded + b"\x00\x00"
        strings = list(carver.carve(data))
        assert any(r"C:\Windows\System32" in s.value for s in strings)


class TestStringCarverMultiEncoding:
    def test_both_ascii_and_utf16(self):
        carver = StringCarver(encodings=["ascii", "utf-16-le"], min_length=4)
        ascii_part = b"Hello"
        utf16_part = "World".encode("utf-16-le")
        data = b"\x00" + ascii_part + b"\x00\x00\x00" + utf16_part + b"\x00\x00"
        strings = list(carver.carve(data))
        encodings_found = {s.encoding for s in strings}
        assert "ascii" in encodings_found


class TestEntropyFiltering:
    def test_high_entropy_skipped(self):
        carver = StringCarver(
            encodings=["ascii"],
            min_length=8,
            entropy_threshold=6.0,
            entropy_window=512,
        )
        # Create a large high-entropy context with an embedded string.
        # Use bytes(range(256))*4 for deterministic high entropy (~8 bits/byte).
        high_ent = bytes(range(256)) * 4  # 1024 bytes, ~8 bits/byte
        # Insert a recognizable string in the middle
        pos = 500
        embedded = b"TestTest"
        data = bytearray(high_ent)
        data[pos : pos + len(embedded)] = embedded
        data = bytes(data)
        strings = list(carver.carve(data))
        # The string should be filtered out because its surrounding context
        # has very high entropy.
        matching = [s for s in strings if s.value == "TestTest"]
        assert len(matching) == 0

    def test_low_entropy_kept(self):
        carver = StringCarver(
            encodings=["ascii"],
            min_length=4,
            entropy_threshold=7.5,
            entropy_window=256,
        )
        data = b"\x00" * 100 + b"Hello World" + b"\x00" * 100
        strings = list(carver.carve(data))
        assert len(strings) == 1


class TestScanInterface:
    def test_scan_yields_scan_results(self):
        carver = StringCarver(encodings=["ascii"], min_length=4)
        data = b"\x00\x00TestString\x00\x00"
        results = list(carver.scan(data, offset=0x500))
        assert len(results) == 1
        assert results[0].offset == 0x502
        assert results[0].rule_name == "string_ascii"
        assert results[0].metadata["string_value"] == "TestString"

    def test_unsupported_encoding_raises(self):
        with pytest.raises(ValueError, match="Unsupported encoding"):
            StringCarver(encodings=["fake-encoding"])

    def test_rule_count(self):
        carver = StringCarver(encodings=["ascii", "utf-16-le", "utf-16-be"])
        assert carver.rule_count == 3
