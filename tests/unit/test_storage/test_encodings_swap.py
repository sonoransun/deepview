"""Tests for LinuxSwapLayer and WindowsSwapLayer."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

import pytest

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.storage.encodings.swap_layer import (
    LINUX_SWAP_MAGIC,
    LINUX_SWAP_MAGIC_OFFSET,
    LINUX_SWAP_PAGE_SIZE,
    LinuxSwapLayer,
    WindowsSwapLayer,
)

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner


class BytesBackingLayer(DataLayer):
    """Minimal in-memory DataLayer used as the raw swap area."""

    def __init__(self, blob: bytes, name: str = "raw_swap") -> None:
        self._blob = bytearray(blob)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            return b""
        end = min(offset + length, len(self._blob))
        out = bytes(self._blob[offset:end])
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        self._blob[offset:offset + len(data)] = data

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._blob)

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        return iter(())

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(len(self._blob) - 1, 0)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name)


def _build_linux_swap_area(total_pages: int, bad_page_indices: list[int]) -> bytes:
    """Build a synthetic Linux v1_01 swap area."""
    last_page = total_pages - 1
    area = bytearray(total_pages * LINUX_SWAP_PAGE_SIZE)
    # version u32 @ 1024.
    area[1024:1028] = (1).to_bytes(4, "little")
    # last_page u32 @ 1028.
    area[1028:1032] = last_page.to_bytes(4, "little")
    # nr_badpages u32 @ 1032.
    area[1032:1036] = len(bad_page_indices).to_bytes(4, "little")
    # Kernel layout: sws_uuid[16]@1036, sws_volume[16]@1052, padding[117]@1068,
    # badpages[] @ 1068 + 117*4 = 1536.
    bad_offset = 1068 + 117 * 4
    for i, idx in enumerate(bad_page_indices):
        area[bad_offset + i * 4:bad_offset + (i + 1) * 4] = idx.to_bytes(4, "little")
    # Magic "SWAPSPACE2" at offset 4086.
    area[LINUX_SWAP_MAGIC_OFFSET:LINUX_SWAP_MAGIC_OFFSET + len(LINUX_SWAP_MAGIC)] = (
        LINUX_SWAP_MAGIC
    )
    # Fill pages 1..last_page with a deterministic pattern so we can verify
    # reads.
    for page in range(1, total_pages):
        fill = bytes([(page & 0xFF)] * LINUX_SWAP_PAGE_SIZE)
        area[page * LINUX_SWAP_PAGE_SIZE:(page + 1) * LINUX_SWAP_PAGE_SIZE] = fill
    return bytes(area)


class TestLinuxSwapLayer:
    def test_header_parsed_and_bounds_correct(self) -> None:
        total_pages = 256  # 1 MiB
        area = _build_linux_swap_area(total_pages, bad_page_indices=[])
        backing = BytesBackingLayer(area)
        layer = LinuxSwapLayer(backing)
        assert layer.last_page == total_pages - 1
        # last_page usable pages -> (total_pages - 1) * PAGE bytes accessible
        assert layer.maximum_address == (total_pages - 1) * LINUX_SWAP_PAGE_SIZE - 1

    def test_good_page_read_matches_backing(self) -> None:
        total_pages = 256
        area = _build_linux_swap_area(total_pages, bad_page_indices=[])
        backing = BytesBackingLayer(area)
        layer = LinuxSwapLayer(backing)
        # Exposed page 0 maps to backing page 1.
        exposed_page = 0
        expected = bytes([1] * LINUX_SWAP_PAGE_SIZE)
        got = layer.read(exposed_page * LINUX_SWAP_PAGE_SIZE, LINUX_SWAP_PAGE_SIZE)
        assert got == expected

    def test_bad_page_reads_zero(self) -> None:
        total_pages = 256
        # Mark backing page 5 as bad. Page 5 in the backing area becomes
        # exposed page 4 (since exposed=backing-1).
        area = _build_linux_swap_area(total_pages, bad_page_indices=[5])
        backing = BytesBackingLayer(area)
        layer = LinuxSwapLayer(backing)
        exposed_page = 4
        got = layer.read(exposed_page * LINUX_SWAP_PAGE_SIZE, LINUX_SWAP_PAGE_SIZE)
        assert got == b"\x00" * LINUX_SWAP_PAGE_SIZE
        # Neighboring good pages remain intact.
        good = layer.read((exposed_page + 1) * LINUX_SWAP_PAGE_SIZE, 16)
        assert good == bytes([6] * 16)

    def test_missing_magic_rejected(self) -> None:
        area = bytearray(LINUX_SWAP_PAGE_SIZE * 4)
        # Set version so that the only failure is the magic.
        area[1024:1028] = (1).to_bytes(4, "little")
        backing = BytesBackingLayer(bytes(area))
        with pytest.raises(ValueError, match="SWAPSPACE2"):
            LinuxSwapLayer(backing)

    def test_wrong_version_rejected(self) -> None:
        area = bytearray(LINUX_SWAP_PAGE_SIZE * 4)
        area[1024:1028] = (2).to_bytes(4, "little")
        area[1028:1032] = (3).to_bytes(4, "little")
        area[LINUX_SWAP_MAGIC_OFFSET:LINUX_SWAP_MAGIC_OFFSET + len(LINUX_SWAP_MAGIC)] = (
            LINUX_SWAP_MAGIC
        )
        backing = BytesBackingLayer(bytes(area))
        with pytest.raises(ValueError, match="version"):
            LinuxSwapLayer(backing)


class TestWindowsSwapLayer:
    def test_passthrough_when_no_runs(self) -> None:
        backing = BytesBackingLayer(b"\xaa" * 1024)
        layer = WindowsSwapLayer(backing)
        assert layer.read(10, 4) == b"\xaa\xaa\xaa\xaa"
        assert layer.is_valid(0, 1024)

    def test_declared_runs_enforced(self) -> None:
        backing = BytesBackingLayer(b"\xbb" * 4096)
        layer = WindowsSwapLayer(backing, valid_runs=[(0, 256), (1024, 256)])
        assert layer.read(0, 16) == b"\xbb" * 16
        assert layer.read(1024, 16) == b"\xbb" * 16
        # Range outside any declared run: pad=True returns zeros.
        assert layer.read(512, 16, pad=True) == b"\x00" * 16
        # Without pad: raises.
        with pytest.raises(ValueError):
            layer.read(512, 16)

    def test_write_raises(self) -> None:
        backing = BytesBackingLayer(b"")
        layer = WindowsSwapLayer(backing)
        with pytest.raises(NotImplementedError):
            layer.write(0, b"X")
