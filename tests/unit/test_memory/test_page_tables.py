"""Tests for page table walking and virtual address translation."""
from __future__ import annotations

import struct

import pytest

from deepview.core.exceptions import TranslationError
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.memory.translation.page_tables import (
    PAGE_2M,
    PAGE_4K,
    PAGE_1G,
    PageTableWalker,
    VirtualMapping,
    _sign_extend,
)
from deepview.memory.translation.virtual_layer import VirtualAddressLayer


# ---------------------------------------------------------------------------
# Minimal in-memory DataLayer for testing
# ---------------------------------------------------------------------------


class FakePhysicalLayer(DataLayer):
    """A simple in-memory DataLayer backed by a bytearray."""

    def __init__(self, size: int = 16 * 1024 * 1024):
        self._data = bytearray(size)

    def write_u64(self, offset: int, value: int) -> None:
        struct.pack_into("<Q", self._data, offset, value)

    def write_bytes(self, offset: int, data: bytes) -> None:
        self._data[offset : offset + len(data)] = data

    # DataLayer interface

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = offset + length
        if end > len(self._data):
            if pad:
                result = self._data[offset:]
                return bytes(result) + b"\x00" * (end - len(self._data))
            raise ValueError(f"Read beyond layer: 0x{offset:x}+{length}")
        return bytes(self._data[offset:end])

    def write(self, offset: int, data: bytes) -> None:
        self._data[offset : offset + len(data)] = data

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and (offset + length) <= len(self._data)

    def scan(self, scanner, progress_callback=None):
        yield from scanner.scan(bytes(self._data), offset=0)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return len(self._data)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name="fake_physical")


# ---------------------------------------------------------------------------
# Constants for building page tables
# ---------------------------------------------------------------------------

PRESENT = 0x1
WRITABLE = 0x2
USER = 0x4
PAGE_SIZE_BIT = 0x80  # PS bit for large pages
NX_BIT = 1 << 63

# Addresses for page table structures (non-overlapping 4K pages)
PML4_ADDR = 0x1000
PDPT_ADDR = 0x2000
PD_ADDR = 0x3000
PT_ADDR = 0x4000
DATA_PAGE_ADDR = 0x5000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_simple_4k_mapping(layer: FakePhysicalLayer) -> int:
    """Build a minimal 4-level page table mapping VA 0x0 -> DATA_PAGE_ADDR.

    Returns the CR3 value (PML4_ADDR).
    """
    # PML4[0] -> PDPT
    layer.write_u64(PML4_ADDR + 0 * 8, PDPT_ADDR | PRESENT | WRITABLE | USER)
    # PDPT[0] -> PD
    layer.write_u64(PDPT_ADDR + 0 * 8, PD_ADDR | PRESENT | WRITABLE | USER)
    # PD[0] -> PT
    layer.write_u64(PD_ADDR + 0 * 8, PT_ADDR | PRESENT | WRITABLE | USER)
    # PT[0] -> data page
    layer.write_u64(PT_ADDR + 0 * 8, DATA_PAGE_ADDR | PRESENT | WRITABLE | USER)
    # Write recognizable data at the physical page
    layer.write_bytes(DATA_PAGE_ADDR, b"HELLO_PAGE_TABLE")
    return PML4_ADDR


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSignExtend:
    def test_positive_value(self):
        assert _sign_extend(0x7F, 8) == 0x7F

    def test_negative_value(self):
        result = _sign_extend(0x80, 8)
        # 0x80 with sign bit set in 8-bit → -128
        assert result == -128

    def test_48bit_canonical(self):
        # Bit 47 clear → positive
        assert _sign_extend(0x0000_7FFF_FFFF_F000, 48) == 0x0000_7FFF_FFFF_F000
        # Bit 47 set → sign extend to negative (kernel space)
        result = _sign_extend(0x0000_8000_0000_0000, 48)
        assert result < 0


class TestPageTableWalker:
    def test_translate_4k_page(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        walker = PageTableWalker(layer)

        result = walker.translate(cr3, 0x0)
        assert result.physical_address == DATA_PAGE_ADDR
        assert result.page_size == PAGE_4K
        assert result.writable is True
        assert result.user is True

    def test_translate_4k_with_offset(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        walker = PageTableWalker(layer)

        result = walker.translate(cr3, 0x10)
        assert result.physical_address == DATA_PAGE_ADDR + 0x10

    def test_translate_not_present_raises(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        walker = PageTableWalker(layer)

        # VA 0x1000 is not mapped (only PT[0] has a present entry)
        with pytest.raises(TranslationError, match="PTE not present"):
            walker.translate(cr3, 0x1000)

    def test_translate_pml4_not_present(self):
        layer = FakePhysicalLayer()
        cr3 = PML4_ADDR  # PML4 is all zeros → not present
        walker = PageTableWalker(layer)

        with pytest.raises(TranslationError, match="PML4E not present"):
            walker.translate(cr3, 0x0)

    def test_translate_2m_large_page(self):
        layer = FakePhysicalLayer()
        large_page_phys = 0x200000  # 2MB-aligned

        layer.write_u64(PML4_ADDR + 0 * 8, PDPT_ADDR | PRESENT | WRITABLE)
        layer.write_u64(PDPT_ADDR + 0 * 8, PD_ADDR | PRESENT | WRITABLE)
        # PD[0] with PS bit → 2MB large page
        layer.write_u64(
            PD_ADDR + 0 * 8, large_page_phys | PRESENT | WRITABLE | PAGE_SIZE_BIT
        )

        walker = PageTableWalker(layer)
        result = walker.translate(PML4_ADDR, 0x0)
        assert result.physical_address == large_page_phys
        assert result.page_size == PAGE_2M

        # Offset within the 2MB page
        result2 = walker.translate(PML4_ADDR, 0x1234)
        assert result2.physical_address == large_page_phys + 0x1234

    def test_translate_1g_large_page(self):
        layer = FakePhysicalLayer(size=2 * PAGE_1G)
        gig_page_phys = 0x40000000  # 1GB-aligned

        layer.write_u64(PML4_ADDR + 0 * 8, PDPT_ADDR | PRESENT | WRITABLE)
        # PDPT[0] with PS bit → 1GB large page
        layer.write_u64(
            PDPT_ADDR + 0 * 8, gig_page_phys | PRESENT | WRITABLE | PAGE_SIZE_BIT
        )

        walker = PageTableWalker(layer)
        result = walker.translate(PML4_ADDR, 0x0)
        assert result.physical_address == gig_page_phys
        assert result.page_size == PAGE_1G

    def test_nx_bit_propagation(self):
        layer = FakePhysicalLayer()
        # Set NX on the PDE level only
        layer.write_u64(PML4_ADDR + 0 * 8, PDPT_ADDR | PRESENT | WRITABLE)
        layer.write_u64(PDPT_ADDR + 0 * 8, PD_ADDR | PRESENT | WRITABLE)
        layer.write_u64(PD_ADDR + 0 * 8, PT_ADDR | PRESENT | WRITABLE | NX_BIT)
        layer.write_u64(PT_ADDR + 0 * 8, DATA_PAGE_ADDR | PRESENT | WRITABLE)

        walker = PageTableWalker(layer)
        result = walker.translate(PML4_ADDR, 0x0)
        assert result.no_execute is True

    def test_walk_all_mappings(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        walker = PageTableWalker(layer)

        mappings = list(walker.walk_all_mappings(cr3))
        assert len(mappings) == 1
        assert mappings[0].virtual_start == 0
        assert mappings[0].physical_start == DATA_PAGE_ADDR
        assert mappings[0].size == PAGE_4K

    def test_walk_multiple_mappings(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        # Add a second mapping at PT[1]
        second_page = 0x6000
        layer.write_u64(PT_ADDR + 1 * 8, second_page | PRESENT | WRITABLE | USER)
        walker = PageTableWalker(layer)

        mappings = list(walker.walk_all_mappings(cr3))
        assert len(mappings) == 2
        assert mappings[1].virtual_start == 0x1000
        assert mappings[1].physical_start == second_page


class TestVirtualAddressLayer:
    def test_read_through_translation(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        data = vlayer.read(0, 16)
        assert data == b"HELLO_PAGE_TABLE"

    def test_read_with_offset(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        data = vlayer.read(6, 10)
        assert data == b"PAGE_TABLE"

    def test_read_unmapped_with_pad(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        # VA 0x2000 is not mapped — pad should return zeros
        data = vlayer.read(0x2000, 8, pad=True)
        assert data == b"\x00" * 8

    def test_read_unmapped_without_pad_raises(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        with pytest.raises(TranslationError):
            vlayer.read(0x2000, 8)

    def test_is_valid(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        assert vlayer.is_valid(0x0) is True
        assert vlayer.is_valid(0x2000) is False

    def test_write_raises(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        with pytest.raises(NotImplementedError):
            vlayer.write(0, b"x")

    def test_get_mappings(self):
        layer = FakePhysicalLayer()
        cr3 = _build_simple_4k_mapping(layer)
        vlayer = VirtualAddressLayer(layer, cr3)

        mappings = vlayer.get_mappings()
        assert len(mappings) == 1
        assert mappings[0].physical_start == DATA_PAGE_ADDR

    def test_metadata(self):
        layer = FakePhysicalLayer()
        vlayer = VirtualAddressLayer(layer, 0x1000, name="test_layer")
        assert vlayer.metadata.name == "test_layer"
