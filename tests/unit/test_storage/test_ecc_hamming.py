"""Hamming SEC/DED codec tests with bit-flip injection."""
from __future__ import annotations

import random

import pytest

from deepview.storage.ecc.hamming import HammingDecoder


@pytest.fixture
def codec() -> HammingDecoder:
    return HammingDecoder()


@pytest.fixture
def sample_data() -> bytes:
    rng = random.Random(0xC0DE)
    return bytes(rng.randrange(0, 256) for _ in range(256))


def test_encode_produces_three_bytes(codec: HammingDecoder, sample_data: bytes) -> None:
    ecc = codec.encode(sample_data)
    assert len(ecc) == 3


def test_clean_roundtrip(codec: HammingDecoder, sample_data: bytes) -> None:
    ecc = codec.encode(sample_data)
    result = codec.decode(sample_data, ecc)
    assert result.data == sample_data
    assert result.errors_corrected == 0
    assert result.uncorrectable is False


@pytest.mark.parametrize("seed", [0, 1, 2, 3, 4, 5, 6, 7])
def test_single_bit_flip_corrects(
    codec: HammingDecoder, sample_data: bytes, seed: int
) -> None:
    ecc = codec.encode(sample_data)
    rng = random.Random(seed)
    byte_idx = rng.randrange(0, 256)
    bit_idx = rng.randrange(0, 8)
    corrupted = bytearray(sample_data)
    corrupted[byte_idx] ^= 1 << bit_idx
    result = codec.decode(bytes(corrupted), ecc)
    assert result.data == sample_data, (
        f"byte={byte_idx} bit={bit_idx} failed to correct"
    )
    assert result.errors_corrected == 1
    assert result.uncorrectable is False


def test_double_bit_flip_same_byte_detected(
    codec: HammingDecoder, sample_data: bytes
) -> None:
    ecc = codec.encode(sample_data)
    corrupted = bytearray(sample_data)
    corrupted[42] ^= 0b0000_0011  # flip two neighboring bits in one byte
    result = codec.decode(bytes(corrupted), ecc)
    assert result.uncorrectable is True
    assert result.errors_corrected == 0


def test_double_bit_flip_cross_byte_detected(
    codec: HammingDecoder, sample_data: bytes
) -> None:
    ecc = codec.encode(sample_data)
    corrupted = bytearray(sample_data)
    corrupted[10] ^= 0x01
    corrupted[200] ^= 0x80
    result = codec.decode(bytes(corrupted), ecc)
    # Different-byte double flip should be flagged uncorrectable (DED).
    assert result.uncorrectable is True


def test_invalid_chunk_size_rejected(codec: HammingDecoder) -> None:
    with pytest.raises(ValueError):
        codec.encode(b"\x00" * 128)
    with pytest.raises(ValueError):
        codec.decode(b"\x00" * 128, b"\x00\x00\x00")
    with pytest.raises(ValueError):
        codec.decode(b"\x00" * 256, b"\x00\x00")
