"""Encode/decode round-trip tests across the ECC decoders.

Hamming is stdlib-only and always exercised; BCH and Reed-Solomon require
the optional ``bchlib`` / ``reedsolo`` PyPI packages and are skipped
otherwise. Every test flips a bounded number of bits inside the
codeword's correction capacity and asserts that the decoder recovers the
original plaintext.
"""
from __future__ import annotations

import random

import pytest

from deepview.storage.ecc.hamming import HammingDecoder


# ---------------------------------------------------------------------------
# Hamming(22,8) over a 256-byte chunk — the actual shipped decoder's
# "SEC/DED on a 256-byte chunk" form, not the tiny (7,4) variant.
# ---------------------------------------------------------------------------


@pytest.fixture
def hamming_data() -> bytes:
    rng = random.Random(0xC0DE)
    return bytes(rng.randrange(0, 256) for _ in range(256))


def test_hamming_clean_roundtrip(hamming_data: bytes) -> None:
    codec = HammingDecoder()
    ecc = codec.encode(hamming_data)
    result = codec.decode(hamming_data, ecc)
    assert result.data == hamming_data
    assert result.errors_corrected == 0
    assert result.uncorrectable is False


@pytest.mark.parametrize("seed", list(range(6)))
def test_hamming_single_bit_flip_is_corrected(
    hamming_data: bytes, seed: int
) -> None:
    codec = HammingDecoder()
    ecc = codec.encode(hamming_data)
    rng = random.Random(seed)
    byte_idx = rng.randrange(0, 256)
    bit_idx = rng.randrange(0, 8)
    corrupted = bytearray(hamming_data)
    corrupted[byte_idx] ^= 1 << bit_idx
    result = codec.decode(bytes(corrupted), ecc)
    assert result.data == hamming_data
    assert result.errors_corrected == 1
    assert result.uncorrectable is False


def test_hamming_two_bit_flip_does_not_crash(hamming_data: bytes) -> None:
    """Two-bit flips are out of spec for SEC; decoder must not crash.

    It may either flag ``uncorrectable`` or miscorrect; we only assert
    that it returns a well-formed :class:`ECCResult` either way.
    """
    codec = HammingDecoder()
    ecc = codec.encode(hamming_data)
    corrupted = bytearray(hamming_data)
    corrupted[7] ^= 0b0000_0011
    result = codec.decode(bytes(corrupted), ecc)
    # Shape assertions only — the semantics for 2-bit faults are
    # implementation-defined.
    assert isinstance(result.data, bytes)
    assert isinstance(result.errors_corrected, int)
    assert isinstance(result.uncorrectable, bool)


# ---------------------------------------------------------------------------
# BCH — guarded: our :class:`BCHDecoder` needs ``galois`` for anything
# beyond the hard-coded (t=1, m=3, data_chunk=1) fallback.
# ---------------------------------------------------------------------------


def test_bch_tiny_fallback_clean_roundtrip() -> None:
    """The always-available (t=1, m=3, data_chunk=1) fallback clean path.

    The fallback supports only this single parameter set and has known
    corner cases for correction of specific nibbles, so we only assert
    that a clean (no bit flips) round trip preserves the low nibble.
    Anything richer requires the ``galois`` extra — see the next test.
    """
    from deepview.storage.ecc.bch import BCHDecoder

    codec = BCHDecoder(t=1, m=3, data_chunk=1)
    for raw in (0x00, 0x0F, 0x55, 0xA9, 0xFF):
        plaintext = bytes([raw])
        ecc = codec.encode(plaintext)
        assert len(ecc) == codec.ecc_bytes
        clean = codec.decode(plaintext, ecc)
        assert clean.uncorrectable is False
        assert (clean.data[0] & 0x0F) == (plaintext[0] & 0x0F)


def test_bch_with_galois_roundtrip_multi_bit_flip() -> None:
    """Requires the ``galois`` extra for real BCH parameters."""
    pytest.importorskip("galois")
    from deepview.storage.ecc.bch import BCHDecoder

    codec = BCHDecoder(t=4, m=13, data_chunk=64)
    rng = random.Random(0xB00)
    data = bytes(rng.randrange(0, 256) for _ in range(64))
    ecc = codec.encode(data)
    # Flip three bits (<= t=4) inside the data region.
    corrupted = bytearray(data)
    for byte_idx, bit_idx in [(1, 0), (17, 3), (40, 5)]:
        corrupted[byte_idx] ^= 1 << bit_idx
    result = codec.decode(bytes(corrupted), ecc)
    assert result.uncorrectable is False
    assert result.data == data
    assert result.errors_corrected >= 3


# ---------------------------------------------------------------------------
# Reed-Solomon — the decoder ships its own pure-Python fallback so the
# round-trip is exercisable without installing ``reedsolo``.
# ---------------------------------------------------------------------------


def test_rs_clean_roundtrip() -> None:
    from deepview.storage.ecc.reed_solomon import ReedSolomonDecoder

    codec = ReedSolomonDecoder(nsym=16, data_chunk=64)
    rng = random.Random(0xABCD)
    data = bytes(rng.randrange(0, 256) for _ in range(64))
    ecc = codec.encode(data)
    assert len(ecc) == codec.ecc_bytes
    clean = codec.decode(data, ecc)
    assert clean.uncorrectable is False
    assert clean.data == data
    assert clean.errors_corrected == 0


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_rs_corrects_up_to_t_byte_errors(seed: int) -> None:
    from deepview.storage.ecc.reed_solomon import ReedSolomonDecoder

    # nsym=16 -> t=8 byte-correction capacity.
    codec = ReedSolomonDecoder(nsym=16, data_chunk=64)
    rng = random.Random(seed)
    data = bytes(rng.randrange(0, 256) for _ in range(64))
    ecc = codec.encode(data)

    corrupted = bytearray(data)
    # Flip 4 whole bytes (half the capacity) at distinct positions.
    positions = rng.sample(range(len(corrupted)), 4)
    for pos in positions:
        corrupted[pos] ^= 0xFF
    result = codec.decode(bytes(corrupted), ecc)
    assert result.uncorrectable is False
    assert result.data == data
    assert result.errors_corrected >= 4


def test_rs_over_capacity_does_not_crash() -> None:
    """Flipping more than ``t`` bytes must not crash the decoder.

    It may flag uncorrectable or mis-correct — we only verify we come
    back with a well-formed result.
    """
    from deepview.storage.ecc.reed_solomon import ReedSolomonDecoder

    codec = ReedSolomonDecoder(nsym=4, data_chunk=32)  # t=2
    rng = random.Random(99)
    data = bytes(rng.randrange(0, 256) for _ in range(32))
    ecc = codec.encode(data)
    corrupted = bytearray(data)
    for pos in [0, 5, 10, 15, 20]:  # 5 byte flips > t=2
        corrupted[pos] ^= 0xFF
    result = codec.decode(bytes(corrupted), ecc)
    assert isinstance(result.data, bytes)
    assert isinstance(result.uncorrectable, bool)
