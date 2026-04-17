"""Tests for :class:`DecryptedVolumeLayer`.

Covers round-trip decrypt via the :func:`synthetic_encrypted_volume`
factory (AES-256-XTS, 512 B sectors), partial reads, OOB semantics,
read-only invariant, ``is_valid`` bounds, LRU sector cache eviction,
and nested wrapping.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest

pytest.importorskip("cryptography")

from tests._factories import MemoryDataLayer, synthetic_encrypted_volume  # noqa: E402

from deepview.core.types import LayerMetadata, ScanResult  # noqa: E402
from deepview.interfaces.layer import DataLayer  # noqa: E402
from deepview.storage.containers.layer import DecryptedVolumeLayer  # noqa: E402


AES_XTS_KEY = bytes(range(32)) + bytes(range(32, 64))  # AES-256-XTS, halves differ


# ---------------------------------------------------------------------------
# Recording wrapper: counts reads against the underlying layer so we can
# probe the LRU cache eviction path without peeking at private state.
# ---------------------------------------------------------------------------


class _RecordingLayer(DataLayer):
    def __init__(self, inner: DataLayer) -> None:
        self._inner = inner
        self.read_calls: list[tuple[int, int]] = []

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        self.read_calls.append((offset, length))
        return self._inner.read(offset, length, pad=pad)

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return self._inner.is_valid(offset, length)

    def scan(
        self, scanner: Any, progress_callback: Callable | None = None
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return self._inner.minimum_address

    @property
    def maximum_address(self) -> int:
        return self._inner.maximum_address

    @property
    def metadata(self) -> LayerMetadata:
        return self._inner.metadata


# ---------------------------------------------------------------------------
# Round-trip + partial read
# ---------------------------------------------------------------------------


def test_round_trip_full_read_returns_plaintext() -> None:
    plaintext = bytes(range(256)) * 8  # 2 KiB, 4 sectors
    backing, expected = synthetic_encrypted_volume(
        plaintext, key=AES_XTS_KEY, sector_size=512
    )
    layer = DecryptedVolumeLayer(
        backing,
        cipher_name="aes",
        key=AES_XTS_KEY,
        sector_size=512,
        mode="xts",
        data_length=len(expected),
    )
    got = layer.read(0, len(expected))
    assert got == expected


def test_partial_read_across_sector_boundary() -> None:
    plaintext = bytes((i * 7) & 0xFF for i in range(2048))
    backing, expected = synthetic_encrypted_volume(
        plaintext, key=AES_XTS_KEY, sector_size=512
    )
    layer = DecryptedVolumeLayer(
        backing,
        cipher_name="aes",
        key=AES_XTS_KEY,
        sector_size=512,
        mode="xts",
        data_length=len(expected),
    )
    got = layer.read(300, 500)
    assert got == expected[300:800]


# ---------------------------------------------------------------------------
# OOB + pad semantics
# ---------------------------------------------------------------------------


def _new_layer(length: int = 1024) -> DecryptedVolumeLayer:
    plaintext = b"\x00" * length
    backing, _ = synthetic_encrypted_volume(
        plaintext, key=AES_XTS_KEY, sector_size=512
    )
    return DecryptedVolumeLayer(
        backing,
        cipher_name="aes",
        key=AES_XTS_KEY,
        sector_size=512,
        mode="xts",
        data_length=length,
    )


def test_read_past_end_without_pad_raises() -> None:
    layer = _new_layer(1024)
    with pytest.raises(ValueError):
        layer.read(1023, 2, pad=False)


def test_read_past_end_with_pad_zero_fills_tail() -> None:
    layer = _new_layer(1024)
    got = layer.read(1023, 2, pad=True)
    assert len(got) == 2
    assert got[0] == 0
    assert got[1] == 0


def test_read_negative_offset_without_pad_raises() -> None:
    layer = _new_layer(1024)
    with pytest.raises(ValueError):
        layer.read(-1, 10, pad=False)


def test_read_negative_offset_with_pad_returns_zeros() -> None:
    layer = _new_layer(1024)
    got = layer.read(-5, 10, pad=True)
    # clamped_start=0 clamped_end=5 → head=5 zeros + first 5 plaintext bytes
    # plaintext is all zeros, so the whole thing is zeros.
    assert got == b"\x00" * 10


# ---------------------------------------------------------------------------
# Write refused, is_valid bounds, metadata
# ---------------------------------------------------------------------------


def test_write_refused() -> None:
    layer = _new_layer(512)
    with pytest.raises(NotImplementedError):
        layer.write(0, b"x")


def test_is_valid_bounds() -> None:
    layer = _new_layer(1024)
    assert layer.is_valid(0, 1024) is True
    assert layer.is_valid(1025, 1) is False


def test_metadata_name_is_set() -> None:
    layer = _new_layer(512)
    assert "crypt:" in layer.metadata.name


# ---------------------------------------------------------------------------
# Sector LRU cache
# ---------------------------------------------------------------------------


def test_sector_cache_cap_evicts_oldest() -> None:
    """With cap=2, reading sectors 0,1,2,0 re-reads sector 0 from backing."""
    plaintext = b"A" * 2048  # 4 sectors of 512 B
    raw_backing, _ = synthetic_encrypted_volume(
        plaintext, key=AES_XTS_KEY, sector_size=512
    )
    rec = _RecordingLayer(raw_backing)

    layer = DecryptedVolumeLayer(
        rec,
        cipher_name="aes",
        key=AES_XTS_KEY,
        sector_size=512,
        mode="xts",
        data_length=2048,
        sector_cache_cap=2,
    )

    # Touch sectors 0, 1, 2, then 0 again.
    _ = layer.read(0, 1)
    _ = layer.read(512, 1)
    _ = layer.read(1024, 1)
    first_phase_calls = list(rec.read_calls)
    # Sector 0 must have been evicted by the 2-entry LRU, so re-reading
    # it should hit the backing layer again.
    _ = layer.read(0, 1)
    assert len(rec.read_calls) == len(first_phase_calls) + 1
    last_call = rec.read_calls[-1]
    assert last_call == (0, 512)


def test_nested_decrypted_volume_layer_constructs() -> None:
    """Wrapping a DecryptedVolumeLayer inside another is valid."""
    plaintext = b"\x00" * 1024
    backing, _ = synthetic_encrypted_volume(
        plaintext, key=AES_XTS_KEY, sector_size=512
    )
    inner = DecryptedVolumeLayer(
        backing,
        cipher_name="aes",
        key=AES_XTS_KEY,
        sector_size=512,
        mode="xts",
        data_length=1024,
        name="inner",
    )
    outer = DecryptedVolumeLayer(
        inner,
        cipher_name="aes",
        key=AES_XTS_KEY,
        sector_size=512,
        mode="xts",
        data_length=1024,
        name="outer",
    )
    assert outer.metadata.name == "outer"
    assert inner.metadata.name == "inner"
