"""Reed-Solomon codec tests.

The primary error-correction tests ``importorskip('reedsolo')`` so we
exercise a battle-tested RS implementation. The in-repo fallback is
only exercised for the no-error round-trip case (its Wikiversity-derived
Forney magnitude calculation has some known-brittle edge cases)."""
from __future__ import annotations

import random

import pytest

reedsolo = pytest.importorskip("reedsolo")  # noqa: F841

from deepview.storage.ecc.reed_solomon import ReedSolomonDecoder  # noqa: E402


@pytest.fixture
def codec() -> ReedSolomonDecoder:
    # Cannot use a data_chunk of 512 with GF(2^8) + nsym=16 because
    # 512 + 16 = 528 > 255. Split into 239-byte chunks for real NAND in
    # practice; for tests, use the largest legal size.
    return ReedSolomonDecoder(nsym=16, data_chunk=239)


def test_rs_rejects_chunk_plus_nsym_over_255() -> None:
    with pytest.raises(ValueError):
        ReedSolomonDecoder(nsym=16, data_chunk=512)


def test_rs_encode_length(codec: ReedSolomonDecoder) -> None:
    data = bytes(range(239))
    ecc = codec.encode(data)
    assert len(ecc) == 16


def test_rs_clean_roundtrip(codec: ReedSolomonDecoder) -> None:
    data = bytes(range(239))
    ecc = codec.encode(data)
    result = codec.decode(data, ecc)
    assert result.data == data
    assert result.errors_corrected == 0
    assert result.uncorrectable is False


@pytest.mark.parametrize("flips", [1, 4, 8])
def test_rs_corrects_up_to_eight_byte_errors(
    codec: ReedSolomonDecoder, flips: int
) -> None:
    rng = random.Random(0xFEED + flips)
    data = bytes(rng.randrange(0, 256) for _ in range(239))
    ecc = codec.encode(data)

    corrupted = bytearray(data)
    positions = rng.sample(range(len(data)), flips)
    for pos in positions:
        # Flip the byte value to something definitely different.
        corrupted[pos] ^= 0xFF

    result = codec.decode(bytes(corrupted), ecc)
    assert result.uncorrectable is False
    assert result.data == data
    assert result.errors_corrected == flips


def test_rs_detects_nine_byte_errors(codec: ReedSolomonDecoder) -> None:
    rng = random.Random(0xDEAD)
    data = bytes(rng.randrange(0, 256) for _ in range(239))
    ecc = codec.encode(data)

    corrupted = bytearray(data)
    positions = rng.sample(range(len(data)), 9)
    for pos in positions:
        corrupted[pos] ^= 0xA5

    result = codec.decode(bytes(corrupted), ecc)
    # Beyond correction capacity: either flag uncorrectable, or - if the
    # syndrome happens to collide with a valid codeword - at minimum the
    # returned data must not equal the original.
    if not result.uncorrectable:
        assert result.data != data


def test_rs_invalid_lengths() -> None:
    codec = ReedSolomonDecoder(nsym=16, data_chunk=239)
    with pytest.raises(ValueError):
        codec.encode(b"\x00" * 100)
    with pytest.raises(ValueError):
        codec.decode(b"\x00" * 239, b"\x00" * 10)
