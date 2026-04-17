"""BCH codec tests. Skips non-trivial parameter sets unless ``galois``
is installed, since the pure-Python fallback only covers BCH(7,4)."""
from __future__ import annotations

import random

import pytest

galois = pytest.importorskip("galois")  # noqa: F841

from deepview.storage.ecc.bch import BCHDecoder  # noqa: E402


@pytest.mark.parametrize("t", [4, 8])
def test_bch_corrects_up_to_t_errors(t: int) -> None:
    codec = BCHDecoder(t=t, m=13, data_chunk=512)
    rng = random.Random(0xBCAA + t)
    data = bytes(rng.randrange(0, 256) for _ in range(512))
    ecc = codec.encode(data)
    assert len(ecc) == codec.ecc_bytes

    # Flip exactly t random bits across the data portion.
    flip_positions = rng.sample(range(len(data) * 8), t)
    corrupted = bytearray(data)
    for bit_pos in flip_positions:
        corrupted[bit_pos >> 3] ^= 1 << (7 - (bit_pos & 7))

    result = codec.decode(bytes(corrupted), ecc)
    assert result.uncorrectable is False
    assert result.data == data
    assert result.errors_corrected == t


@pytest.mark.parametrize("t", [4, 8])
def test_bch_detects_over_t_errors(t: int) -> None:
    codec = BCHDecoder(t=t, m=13, data_chunk=512)
    rng = random.Random(0xD1EE + t)
    data = bytes(rng.randrange(0, 256) for _ in range(512))
    ecc = codec.encode(data)

    # Flip t+1 random bits.
    flip_positions = rng.sample(range(len(data) * 8), t + 1)
    corrupted = bytearray(data)
    for bit_pos in flip_positions:
        corrupted[bit_pos >> 3] ^= 1 << (7 - (bit_pos & 7))

    result = codec.decode(bytes(corrupted), ecc)
    # With t+1 errors the decoder either flags uncorrectable or, if it
    # mis-decodes, returns data that does NOT equal the original.
    if not result.uncorrectable:
        assert result.data != data


def test_bch_invalid_lengths() -> None:
    codec = BCHDecoder(t=4, m=13, data_chunk=512)
    with pytest.raises(ValueError):
        codec.encode(b"\x00" * 256)
    with pytest.raises(ValueError):
        codec.decode(b"\x00" * 512, b"\x00")
