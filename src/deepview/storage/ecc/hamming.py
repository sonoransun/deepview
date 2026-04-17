"""SmartMedia-style 256-byte Hamming SEC/DED decoder.

Implements the classic SmartMedia Hamming code covering 256 bytes of
data with 22 parity bits packed into 3 bytes (the low two bits of byte2
are constant padding). Capable of single-bit error correction (SEC) and
double-bit error detection (DED) per 256-byte chunk. Pure Python; no
optional dependencies.

Layout of the three parity bytes (matches the widely deployed SmartMedia
convention used by the Linux MTD ``nand_ecc`` helper):

  byte0:   LP07 LP06 LP05 LP04 LP03 LP02 LP01 LP00
  byte1:   LP15 LP14 LP13 LP12 LP11 LP10 LP09 LP08
  byte2:   CP5  CP4  CP3  CP2  CP1  CP0   1    1

Where LPn is a line (row) parity covering byte indices grouped by bit n/2
of the index and CP0..CP5 are 3 column-parity pairs over the 8-bit
page width.

For each pair (odd, even) a valid SEC syndrome has exactly one of the
two bits set (XOR == 1). If every pair in the non-zero syndrome obeys
this rule, the error is single-bit and we can reconstruct the byte and
bit index from the "odd" half of each pair. Otherwise the block has a
multi-bit error and is flagged uncorrectable.
"""
from __future__ import annotations

from deepview.interfaces.ecc import ECCDecoder, ECCResult


_BIT_PARITY = [bin(i).count("1") & 1 for i in range(256)]


def _compute_parity(chunk: bytes) -> tuple[int, int, int]:
    """Return (byte0, byte1, byte2) SmartMedia-style Hamming parity."""
    # Column parity byte: XOR of all 256 data bytes.
    col = 0
    for b in chunk:
        col ^= b
    col &= 0xFF

    # Column-parity partial sums over the 8 bit positions of ``col``.
    bits = [(col >> i) & 1 for i in range(8)]
    cp0 = bits[1] ^ bits[3] ^ bits[5] ^ bits[7]
    cp1 = bits[2] ^ bits[3] ^ bits[6] ^ bits[7]
    cp2 = bits[4] ^ bits[5] ^ bits[6] ^ bits[7]
    cp0c = bits[0] ^ bits[2] ^ bits[4] ^ bits[6]
    cp1c = bits[0] ^ bits[1] ^ bits[4] ^ bits[5]
    cp2c = bits[0] ^ bits[1] ^ bits[2] ^ bits[3]

    # Line parities across the 256 rows, in 8 pair groupings keyed by
    # bit n of the byte index. Each "odd" parity takes bytes where the
    # bit is 1, each "even" takes bytes where the bit is 0.
    # We accumulate the per-byte bit-parity into each of 16 buckets.
    lp = [0] * 16  # LP00..LP15
    for i, b in enumerate(chunk):
        p = _BIT_PARITY[b]
        if not p:
            continue
        # Pair 0 = index bit 0 -> (LP01 odd, LP00 even)
        # Pair 1 = index bit 1 -> (LP03 odd, LP02 even)
        # ... Pair 7 = index bit 7 -> (LP15 odd, LP14 even)
        for k in range(8):
            pair_odd = 2 * k + 1
            pair_even = 2 * k
            if (i >> k) & 1:
                lp[pair_odd] ^= 1
            else:
                lp[pair_even] ^= 1

    byte0 = (
        (lp[7] << 7)
        | (lp[6] << 6)
        | (lp[5] << 5)
        | (lp[4] << 4)
        | (lp[3] << 3)
        | (lp[2] << 2)
        | (lp[1] << 1)
        | lp[0]
    )
    byte1 = (
        (lp[15] << 7)
        | (lp[14] << 6)
        | (lp[13] << 5)
        | (lp[12] << 4)
        | (lp[11] << 3)
        | (lp[10] << 2)
        | (lp[9] << 1)
        | lp[8]
    )
    byte2 = (
        (cp2 << 7)
        | (cp2c << 6)
        | (cp1 << 5)
        | (cp1c << 4)
        | (cp0 << 3)
        | (cp0c << 2)
        | 0x03
    )
    return byte0, byte1, byte2


def _pair_one_set(byte: int, start_pair: int, count_pairs: int) -> bool:
    """Check that every pair within ``byte`` has exactly one bit set."""
    for k in range(start_pair, start_pair + count_pairs):
        hi = (byte >> (2 * k + 1)) & 1
        lo = (byte >> (2 * k)) & 1
        if (hi ^ lo) != 1:
            return False
    return True


class HammingDecoder(ECCDecoder):
    """SmartMedia-style 256-byte Hamming (22,8) SEC/DED codec."""

    name = "hamming256"
    data_chunk = 256
    ecc_bytes = 3

    def encode(self, data: bytes) -> bytes:
        if len(data) != self.data_chunk:
            raise ValueError(
                f"hamming encode expects {self.data_chunk} bytes, got {len(data)}"
            )
        b0, b1, b2 = _compute_parity(data)
        return bytes((b0, b1, b2))

    def decode(self, data: bytes, ecc: bytes) -> ECCResult:
        if len(data) != self.data_chunk:
            raise ValueError(
                f"hamming decode expects {self.data_chunk} data bytes, got {len(data)}"
            )
        if len(ecc) != self.ecc_bytes:
            raise ValueError(
                f"hamming decode expects {self.ecc_bytes} ecc bytes, got {len(ecc)}"
            )

        expected = _compute_parity(data)
        s0 = expected[0] ^ ecc[0]
        s1 = expected[1] ^ ecc[1]
        s2 = expected[2] ^ ecc[2]

        if s0 == 0 and s1 == 0 and s2 == 0:
            return ECCResult(data=bytes(data), errors_corrected=0, uncorrectable=False)

        # For SEC every bit-pair in the non-zero syndrome must XOR to 1.
        # byte2's low two bits are always 0 in the syndrome (both
        # expected and stored hold 0x03 there).
        sec0 = _pair_one_set(s0, 0, 4)
        sec1 = _pair_one_set(s1, 0, 4)
        sec2 = _pair_one_set(s2, 1, 3)
        if not (sec0 and sec1 and sec2):
            return ECCResult(data=bytes(data), errors_corrected=0, uncorrectable=True)

        # Extract the byte index from the 8 LP "odd" bits (LP01..LP15 at
        # bit positions 1,3,5,7 of byte0 and byte1).
        byte_index = (
            ((s0 >> 1) & 1)
            | (((s0 >> 3) & 1) << 1)
            | (((s0 >> 5) & 1) << 2)
            | (((s0 >> 7) & 1) << 3)
            | (((s1 >> 1) & 1) << 4)
            | (((s1 >> 3) & 1) << 5)
            | (((s1 >> 5) & 1) << 6)
            | (((s1 >> 7) & 1) << 7)
        )
        bit_index = ((s2 >> 3) & 1) | (((s2 >> 5) & 1) << 1) | (((s2 >> 7) & 1) << 2)

        if byte_index >= self.data_chunk:
            return ECCResult(data=bytes(data), errors_corrected=0, uncorrectable=True)

        corrected = bytearray(data)
        corrected[byte_index] ^= 1 << bit_index
        return ECCResult(data=bytes(corrected), errors_corrected=1, uncorrectable=False)
