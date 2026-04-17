"""Round-trip tests for the AF-split helper."""
from __future__ import annotations

import hashlib
import os

import pytest

from deepview.storage.containers._af_split import af_merge, af_split


def test_af_split_merge_roundtrip_sha1() -> None:
    key = bytes(range(32))  # 32-byte master key
    stripes = 4000  # LUKS1 default
    random_bytes = os.urandom(32 * (stripes - 1))
    merged_input = af_split(key, stripes, random_bytes, hash_name="sha1")
    recovered = af_merge(merged_input, keylen=32, stripe_count=stripes, hash_name="sha1")
    assert recovered == key


def test_af_split_merge_roundtrip_sha256_small() -> None:
    # Smaller stripe count + sha256 — exercises the LUKS2 path.
    key = b"\x11" * 16
    stripes = 100
    random_bytes = b"\xAB" * (16 * (stripes - 1))
    merged_input = af_split(key, stripes, random_bytes, hash_name="sha256")
    recovered = af_merge(
        merged_input, keylen=16, stripe_count=stripes, hash_name="sha256"
    )
    assert recovered == key


def test_af_merge_single_stripe_is_identity() -> None:
    # stripe_count == 1 means there is only the final XOR-chunk; the
    # merged key is the stripe itself.
    key = b"\x42" * 16
    recovered = af_merge(key, keylen=16, stripe_count=1, hash_name="sha1")
    assert recovered == key


def test_af_merge_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        af_merge(b"\x00" * 31, keylen=32, stripe_count=1, hash_name="sha1")


def test_af_split_rejects_wrong_random_length() -> None:
    with pytest.raises(ValueError):
        af_split(b"\x00" * 16, stripe_count=4, random_bytes=b"\x00", hash_name="sha1")


def test_af_merge_is_deterministic() -> None:
    # A fixed deterministic input produces the same output twice.
    key = hashlib.sha1(b"deterministic").digest()
    stripes = 8
    random_bytes = hashlib.sha256(b"fixture").digest() * ((20 * (stripes - 1)) // 32 + 1)
    random_bytes = random_bytes[: 20 * (stripes - 1)]
    merged_input = af_split(key, stripes, random_bytes, hash_name="sha1")
    a = af_merge(merged_input, keylen=20, stripe_count=stripes, hash_name="sha1")
    b = af_merge(merged_input, keylen=20, stripe_count=stripes, hash_name="sha1")
    assert a == b == key
