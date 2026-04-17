"""Microsoft Xpress compression decoders (MS-XCA).

Two closely-related algorithms are implemented here:

* **Plain Xpress** (LZ77 family) — fully implemented. Used by the Windows
  hibernation file page runs and a handful of other OS artefacts.
* **Xpress-Huffman** — stubbed: the outer 64 KiB block framing is recognised
  but the inner Huffman tree decoder is intentionally left unimplemented,
  as the full prefix-code table walking is several hundred additional lines.
  Callers receive a :class:`NotImplementedError` with the reason.

Both functions are pure Python and have no dependencies outside the stdlib.

References
----------
* [MS-XCA] — *Xpress Compression Algorithm* (Microsoft Open Specifications).
* ReactOS / Wine reference implementations (compared against for correctness).
"""
from __future__ import annotations

from typing import Final

__all__ = ["decompress_xpress", "decompress_xpress_huffman"]


_MIN_MATCH: Final[int] = 3


def decompress_xpress(buf: bytes, expected_size: int) -> bytes:
    """Decompress a plain Xpress (LZ77) stream.

    Parameters
    ----------
    buf:
        The raw compressed byte stream.
    expected_size:
        The caller's expectation for the *uncompressed* size, in bytes. The
        decoder will produce up to this many bytes and stop; if the input
        stream is exhausted earlier, the returned buffer will be shorter.

    Returns
    -------
    bytes
        The decompressed output. May be shorter than *expected_size* if the
        input is truncated, but never longer.

    Raises
    ------
    ValueError
        If the compressed stream is structurally malformed (e.g. a back-
        reference points before the start of the output buffer).
    """
    if expected_size < 0:
        raise ValueError("expected_size must be non-negative")
    out = bytearray()
    input_position = 0
    output_position = 0
    input_len = len(buf)
    # Running 32-bit flag word; the low bit (after shifting) is consumed
    # on each iteration and indicates whether the next token is a literal
    # byte (0) or a back-reference (1). When ``nibble_index`` reaches 32
    # we reload from the stream.
    flags: int = 0
    flag_count: int = 0
    # Holds the index of a nibble that has already been used once (the low
    # 4 bits of a shared byte). ``-1`` means "no pending nibble".
    nibble_index: int = -1

    while output_position < expected_size:
        if flag_count == 0:
            if input_position + 4 > input_len:
                break
            flags = int.from_bytes(buf[input_position:input_position + 4], "little")
            input_position += 4
            flag_count = 32

        # Consume the MSB of the flag word (MS-XCA §2.4: bit 31 first).
        if (flags & 0x80000000) == 0:
            # Literal byte.
            if input_position >= input_len:
                break
            out.append(buf[input_position])
            input_position += 1
            output_position += 1
        else:
            # Back-reference: 16-bit descriptor, low 3 bits are the base
            # length, upper 13 bits are the (offset - 1).
            if input_position + 2 > input_len:
                break
            descriptor = int.from_bytes(buf[input_position:input_position + 2], "little")
            input_position += 2
            match_offset = (descriptor >> 3) + 1
            match_length = descriptor & 0x7

            if match_length == 7:
                # Length >= 10: read an additional nibble (half-byte).
                if nibble_index < 0:
                    if input_position >= input_len:
                        break
                    nibble = buf[input_position] & 0x0F
                    nibble_index = input_position
                    input_position += 1
                else:
                    nibble = (buf[nibble_index] >> 4) & 0x0F
                    nibble_index = -1
                match_length = nibble

                if match_length == 15:
                    # Length >= 25: read a full extension byte.
                    if input_position >= input_len:
                        break
                    match_length = buf[input_position]
                    input_position += 1

                    if match_length == 255:
                        # Length >= 280: read a 16-bit absolute length.
                        if input_position + 2 > input_len:
                            break
                        match_length = int.from_bytes(
                            buf[input_position:input_position + 2], "little"
                        )
                        input_position += 2
                        if match_length < 15 + 7:
                            raise ValueError("Xpress: invalid extended match length")
                        match_length -= 15 + 7
                    match_length += 15
                match_length += 7
            match_length += _MIN_MATCH

            if match_offset > output_position:
                raise ValueError(
                    "Xpress: match offset points before start of output "
                    f"(offset={match_offset}, output_position={output_position})"
                )

            # Copy ``match_length`` bytes, one at a time — overlapping copies
            # (offset < length) are legitimate and yield RLE-style runs.
            src = output_position - match_offset
            for i in range(match_length):
                if output_position >= expected_size:
                    break
                out.append(out[src + i])
                output_position += 1

        flags = (flags << 1) & 0xFFFFFFFF
        flag_count -= 1

    return bytes(out)


def decompress_xpress_huffman(buf: bytes, expected_size: int) -> bytes:
    """Decompress an Xpress-Huffman stream.

    The Xpress-Huffman format (MS-XCA §2.3) frames its input into 65536-byte
    output blocks. Each block is preceded by a 256-byte Huffman code-length
    table encoding the prefix codes for the 512-symbol alphabet (0-255 are
    literals; 256-511 are match descriptors). This decoder recognises the
    framing but *does not* implement the Huffman table reconstruction or the
    symbol-stream bit decoder — that path is intentionally left as a
    ``NotImplementedError`` so downstream callers can decide whether to
    fall back to an external library (e.g. ``python-pyxpress``) or skip the
    page.

    Callers that only need plain Xpress should use :func:`decompress_xpress`
    directly.
    """
    if expected_size < 0:
        raise ValueError("expected_size must be non-negative")
    if len(buf) < 256:
        raise ValueError("Xpress-Huffman: compressed stream shorter than code table")
    # We could parse the code-length table header here, but without the full
    # prefix-code decoder it's pointless and misleading. Fail loud.
    raise NotImplementedError(
        "Xpress-Huffman: full Huffman prefix-code decoder not implemented in "
        "pure-Python fallback; install an Xpress-Huffman extension or pre-"
        "decompress the stream"
    )
