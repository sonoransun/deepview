"""Tests for the plain Xpress (MS-XCA) decoder.

We exercise the decoder against hand-crafted compressed buffers whose
structure we understand bit-for-bit. Building a symmetric encoder is
significantly more work than building a decoder (you need to run a LZ77
match-finder), so these tests use:

1. An all-literals stream (flag=0x00000000) — trivially constructed.
2. A tiny stream with one literal + one short back-reference — lets us
   verify the descriptor/bit-consumption ordering end-to-end.
3. A stream with an overlapping back-reference (offset < length) — the
   classic RLE test case that catches "copied the wrong direction" bugs.
"""
from __future__ import annotations

import pytest

from deepview.storage.encodings.xpress import (
    decompress_xpress,
    decompress_xpress_huffman,
)


def _literals_block(payload: bytes) -> bytes:
    """Build an all-literal Xpress block from *payload*.

    Each 32 flag-bits encode "literal, literal, literal, ..." (flag=0).
    We always emit a flag word of 0x00000000 before every 32 tokens.
    """
    out = bytearray()
    i = 0
    n = len(payload)
    while i < n:
        out.extend(b"\x00\x00\x00\x00")  # flag word: 32 literals
        take = min(32, n - i)
        out.extend(payload[i:i + take])
        i += take
    return bytes(out)


class TestDecompressXpressLiterals:
    def test_all_literals_short(self) -> None:
        payload = b"Hello, Xpress!"
        compressed = _literals_block(payload)
        assert decompress_xpress(compressed, len(payload)) == payload

    def test_all_literals_exact_32(self) -> None:
        payload = bytes(range(32))
        compressed = _literals_block(payload)
        assert decompress_xpress(compressed, 32) == payload

    def test_all_literals_multi_block(self) -> None:
        # 70 bytes forces three flag-word refills (32 + 32 + 6).
        payload = bytes((i * 7 + 3) & 0xFF for i in range(70))
        compressed = _literals_block(payload)
        assert decompress_xpress(compressed, 70) == payload

    def test_expected_size_truncates(self) -> None:
        payload = b"ABCDEFG"
        compressed = _literals_block(payload)
        assert decompress_xpress(compressed, 3) == b"ABC"

    def test_negative_expected_size_rejected(self) -> None:
        with pytest.raises(ValueError):
            decompress_xpress(b"", -1)


class TestDecompressXpressBackref:
    def test_literal_then_short_backref(self) -> None:
        """Emit 'A' as literal, then a 3-byte match at offset 1 -> 'AAAA'."""
        # Flag layout (MSB first): bit31=0 (literal 'A'), bit30=1 (match),
        # remaining 30 bits don't matter so long as we stop after output is
        # full.
        flag = 0b01 << 30  # 0x40000000
        out = bytearray()
        out.extend(flag.to_bytes(4, "little"))
        out.append(ord("A"))
        # descriptor: offset=1 encoded as (offset-1)=0 in upper 13 bits,
        # length=3 encoded as length-3=0 in low 3 bits -> 0x0000.
        out.extend((0x0000).to_bytes(2, "little"))
        # Followed by padding literals that will never be consumed (we stop
        # once expected_size is reached).
        out.extend(b"\x00" * 4)
        got = decompress_xpress(bytes(out), expected_size=4)
        assert got == b"AAAA"

    def test_rle_overlapping_backref(self) -> None:
        """Classic RLE pattern: literal 'X', then a length-7 match at offset 1."""
        # bit31=0 (literal), bit30=1 (match), rest arbitrary.
        flag = 0b01 << 30
        out = bytearray()
        out.extend(flag.to_bytes(4, "little"))
        out.append(ord("X"))
        # offset=1 -> (offset-1)=0 in upper 13 bits
        # length=7 requested -> descriptor low 3 bits = (7 - 3) = 4 (no
        # extension needed).
        descriptor = (0 << 3) | 4
        out.extend(descriptor.to_bytes(2, "little"))
        got = decompress_xpress(bytes(out), expected_size=8)
        assert got == b"X" * 8

    def test_backref_before_start_raises(self) -> None:
        """A back-reference whose offset exceeds output_position must raise."""
        # First token is a match (bit31=1); offset=1, length=3 -> needs 1
        # byte already written, but nothing has been written yet.
        flag = 0b1 << 31
        out = bytearray()
        out.extend(flag.to_bytes(4, "little"))
        out.extend((0x0000).to_bytes(2, "little"))
        with pytest.raises(ValueError):
            decompress_xpress(bytes(out), expected_size=4)


class TestDecompressXpressExtendedLength:
    """Cover the nibble / byte / u16 length-extension ladder.

    Length encoding (MS-XCA §2.4): the descriptor's low 3 bits hold
    ``length - 3`` when < 7; the value 7 escapes to a 4-bit nibble, the
    nibble value 15 escapes to a full extension byte, and the byte value 255
    escapes to a 16-bit absolute length holding ``length - 3``.
    """

    @staticmethod
    def _literal_then_match(literal: int, descriptor: int, tail: bytes) -> bytes:
        # bit31=0 (literal), bit30=1 (match at offset 1).
        flag = 0b01 << 30
        out = bytearray()
        out.extend(flag.to_bytes(4, "little"))
        out.append(literal)
        out.extend(descriptor.to_bytes(2, "little"))
        out.extend(tail)
        return bytes(out)

    def test_nibble_extension(self) -> None:
        # low3 = 7 escapes to a nibble; nibble = 5 (< 15) -> final length
        # 7 (escape base) + 5 (nibble) + 3 (MIN_MATCH) = 15 copied bytes.
        descriptor = (0 << 3) | 7  # offset 1
        compressed = self._literal_then_match(ord("A"), descriptor, bytes([0x05]))
        got = decompress_xpress(compressed, expected_size=64)
        assert got == b"A" * 16  # 1 literal + 15 match

    def test_nibble_high_half_reused(self) -> None:
        # Two consecutive nibble-extended matches share a single nibble byte:
        # the first match reads the low nibble (consuming the byte) and the
        # second reuses the byte's high nibble. The shared byte is emitted
        # inline right after the first descriptor, before the second.
        flag = 0b011 << 29  # literal, match, match (MSB-first)
        out = bytearray()
        out.extend(flag.to_bytes(4, "little"))
        out.append(ord("Z"))
        # Match 1: offset 1, low3 = 7 -> read nibble.
        out.extend(((0 << 3) | 7).to_bytes(2, "little"))
        # Shared nibble byte: low half = 1 (match 1), high half = 2 (match 2).
        out.append(0x21)
        # Match 2: offset 1, low3 = 7 -> reuse the high nibble (no byte read).
        out.extend(((0 << 3) | 7).to_bytes(2, "little"))
        got = decompress_xpress(bytes(out), expected_size=64)
        # Match1: 7 + 1 + 3 = 11; Match2: 7 + 2 + 3 = 12; +1 literal = 24.
        assert got == b"Z" * 24

    def test_full_byte_extension(self) -> None:
        # low3 = 7, nibble = 15 -> read a byte; byte = 100 (< 255).
        # final length = 100 + 15 + 7 + 3 = 125.
        descriptor = (0 << 3) | 7
        compressed = self._literal_then_match(ord("B"), descriptor, bytes([0x0F, 100]))
        got = decompress_xpress(compressed, expected_size=4096)
        assert got == b"B" * 126  # 1 literal + 125 match

    def test_u16_extension(self) -> None:
        # low3 = 7, nibble = 15, byte = 255 -> read u16 holding length-3.
        # u16 = 500 -> final length = 500 - 22 + 25 = 503.
        descriptor = (0 << 3) | 7
        tail = bytes([0x0F, 255]) + (500).to_bytes(2, "little")
        compressed = self._literal_then_match(ord("C"), descriptor, tail)
        got = decompress_xpress(compressed, expected_size=8192)
        assert got == b"C" * 504  # 1 literal + 503 match

    def test_u16_extension_underflow_rejected(self) -> None:
        # A u16 length field below the 15+7 constant would underflow; the
        # decoder must reject it instead of producing a negative length.
        descriptor = (0 << 3) | 7
        tail = bytes([0x0F, 255]) + (5).to_bytes(2, "little")
        compressed = self._literal_then_match(ord("D"), descriptor, tail)
        with pytest.raises(ValueError, match="extended match length"):
            decompress_xpress(compressed, expected_size=8192)


class TestDecompressXpressTruncated:
    def test_truncated_flag_word_stops_cleanly(self) -> None:
        # Only 3 bytes of flag word -> no output, no crash.
        assert decompress_xpress(b"\x00\x00\x00", expected_size=16) == b""

    def test_empty_input_empty_output(self) -> None:
        assert decompress_xpress(b"", expected_size=16) == b""


class TestDecompressXpressHuffman:
    def test_stub_raises_not_implemented(self) -> None:
        # 256-byte minimum code table + a few payload bytes.
        buf = b"\x00" * 260
        with pytest.raises(NotImplementedError, match="Xpress-Huffman"):
            decompress_xpress_huffman(buf, expected_size=65536)

    def test_too_short_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            decompress_xpress_huffman(b"\x00" * 10, expected_size=65536)

    def test_negative_expected_size_rejected(self) -> None:
        with pytest.raises(ValueError):
            decompress_xpress_huffman(b"\x00" * 300, expected_size=-1)
