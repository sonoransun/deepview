"""Page table walking for x86-64 (4-level and 5-level paging).

Implements the CR3 → PML4/PML5 → PDPT → PD → PT walk described in
Intel SDM Vol. 3A, Chapter 4. Operates directly on a physical DataLayer
without relying on OS kernel structures, making it useful when those
structures are corrupted or manipulated by anti-forensics.

References:
    - Intel SDM Vol. 3A, Ch. 4 (Paging)
    - Dolan-Gavitt, "Robust Forensic Process Enumeration"
    - Volatility 3 intel.py layer (conceptual basis)
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from deepview.core.exceptions import TranslationError

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer


# Page table entry flag bits
_PRESENT = 1 << 0
_WRITABLE = 1 << 1
_USER = 1 << 2
_PAGE_SIZE = 1 << 7  # PS bit — indicates large page at PDE/PDPTE level
_NX = 1 << 63

# Address masks
_PHYS_ADDR_MASK_4K = 0x000F_FFFF_FFFF_F000  # Bits 51:12
_PHYS_ADDR_MASK_2M = 0x000F_FFFF_FFE0_0000  # Bits 51:21
_PHYS_ADDR_MASK_1G = 0x000F_FFFF_C000_0000  # Bits 51:30

# Page sizes
PAGE_4K = 4096
PAGE_2M = 2 * 1024 * 1024
PAGE_1G = 1024 * 1024 * 1024


@dataclass(slots=True)
class VirtualMapping:
    """A single virtual-to-physical memory mapping."""

    virtual_start: int
    physical_start: int
    size: int
    writable: bool
    user: bool
    no_execute: bool
    level: int  # 1=4K, 2=2M, 3=1G


@dataclass(slots=True)
class TranslationResult:
    """Result of a single virtual address translation."""

    physical_address: int
    page_size: int
    writable: bool
    user: bool
    no_execute: bool


class PageTableWalker:
    """Walk x86-64 page tables on a physical memory DataLayer.

    Supports both 4-level (standard x86-64) and 5-level paging (LA57).
    """

    def __init__(self, layer: DataLayer, *, five_level: bool = False):
        self._layer = layer
        self._five_level = five_level

    def _read_entry(self, physical_addr: int) -> int:
        """Read a single 8-byte page table entry from physical memory."""
        try:
            data = self._layer.read(physical_addr, 8, pad=False)
        except Exception as exc:
            raise TranslationError(
                f"Cannot read page table entry at physical 0x{physical_addr:x}"
            ) from exc
        return struct.unpack("<Q", data)[0]

    def translate(self, cr3: int, virtual_address: int) -> TranslationResult:
        """Translate a virtual address to a physical address.

        Args:
            cr3: Value of the CR3 register (page directory base).
            virtual_address: 64-bit virtual address to translate.

        Returns:
            TranslationResult with physical address and page metadata.

        Raises:
            TranslationError: If any page table entry is not present.
        """
        va = virtual_address

        # Extract indices for each level (9 bits each)
        if self._five_level:
            pml5_idx = (va >> 48) & 0x1FF
        pml4_idx = (va >> 39) & 0x1FF
        pdpt_idx = (va >> 30) & 0x1FF
        pd_idx = (va >> 21) & 0x1FF
        pt_idx = (va >> 12) & 0x1FF
        offset_4k = va & 0xFFF

        pml4_base = cr3 & _PHYS_ADDR_MASK_4K

        # Accumulate permission bits (AND across levels)
        writable = True
        user = True
        nx = False

        # PML5 (5-level paging only)
        if self._five_level:
            pml5e = self._read_entry(pml4_base + pml5_idx * 8)
            if not (pml5e & _PRESENT):
                raise TranslationError(
                    f"PML5E not present for VA 0x{va:x} (index {pml5_idx})"
                )
            writable &= bool(pml5e & _WRITABLE)
            user &= bool(pml5e & _USER)
            nx |= bool(pml5e & _NX)
            pml4_base = pml5e & _PHYS_ADDR_MASK_4K

        # PML4
        pml4e = self._read_entry(pml4_base + pml4_idx * 8)
        if not (pml4e & _PRESENT):
            raise TranslationError(
                f"PML4E not present for VA 0x{va:x} (index {pml4_idx})"
            )
        writable &= bool(pml4e & _WRITABLE)
        user &= bool(pml4e & _USER)
        nx |= bool(pml4e & _NX)

        # PDPT
        pdpt_base = pml4e & _PHYS_ADDR_MASK_4K
        pdpte = self._read_entry(pdpt_base + pdpt_idx * 8)
        if not (pdpte & _PRESENT):
            raise TranslationError(
                f"PDPTE not present for VA 0x{va:x} (index {pdpt_idx})"
            )
        writable &= bool(pdpte & _WRITABLE)
        user &= bool(pdpte & _USER)
        nx |= bool(pdpte & _NX)

        # 1GB page?
        if pdpte & _PAGE_SIZE:
            phys = (pdpte & _PHYS_ADDR_MASK_1G) | (va & (PAGE_1G - 1))
            return TranslationResult(phys, PAGE_1G, writable, user, nx)

        # PD
        pd_base = pdpte & _PHYS_ADDR_MASK_4K
        pde = self._read_entry(pd_base + pd_idx * 8)
        if not (pde & _PRESENT):
            raise TranslationError(
                f"PDE not present for VA 0x{va:x} (index {pd_idx})"
            )
        writable &= bool(pde & _WRITABLE)
        user &= bool(pde & _USER)
        nx |= bool(pde & _NX)

        # 2MB page?
        if pde & _PAGE_SIZE:
            phys = (pde & _PHYS_ADDR_MASK_2M) | (va & (PAGE_2M - 1))
            return TranslationResult(phys, PAGE_2M, writable, user, nx)

        # PT (4KB page)
        pt_base = pde & _PHYS_ADDR_MASK_4K
        pte = self._read_entry(pt_base + pt_idx * 8)
        if not (pte & _PRESENT):
            raise TranslationError(
                f"PTE not present for VA 0x{va:x} (index {pt_idx})"
            )
        writable &= bool(pte & _WRITABLE)
        user &= bool(pte & _USER)
        nx |= bool(pte & _NX)

        phys = (pte & _PHYS_ADDR_MASK_4K) | offset_4k
        return TranslationResult(phys, PAGE_4K, writable, user, nx)

    def walk_all_mappings(self, cr3: int) -> Iterator[VirtualMapping]:
        """Enumerate all valid virtual-to-physical mappings for an address space.

        Yields VirtualMapping for every present page found in the page tables.
        """
        pml4_base = cr3 & _PHYS_ADDR_MASK_4K

        for pml4_idx in range(512):
            try:
                pml4e = self._read_entry(pml4_base + pml4_idx * 8)
            except TranslationError:
                continue
            if not (pml4e & _PRESENT):
                continue

            pdpt_base = pml4e & _PHYS_ADDR_MASK_4K
            va_pml4 = _sign_extend(pml4_idx << 39, 48)

            for pdpt_idx in range(512):
                try:
                    pdpte = self._read_entry(pdpt_base + pdpt_idx * 8)
                except TranslationError:
                    continue
                if not (pdpte & _PRESENT):
                    continue

                va_pdpt = va_pml4 | (pdpt_idx << 30)

                # 1GB large page
                if pdpte & _PAGE_SIZE:
                    yield VirtualMapping(
                        virtual_start=va_pdpt,
                        physical_start=pdpte & _PHYS_ADDR_MASK_1G,
                        size=PAGE_1G,
                        writable=bool(pml4e & _WRITABLE and pdpte & _WRITABLE),
                        user=bool(pml4e & _USER and pdpte & _USER),
                        no_execute=bool(pml4e & _NX or pdpte & _NX),
                        level=3,
                    )
                    continue

                pd_base = pdpte & _PHYS_ADDR_MASK_4K
                for pd_idx in range(512):
                    try:
                        pde = self._read_entry(pd_base + pd_idx * 8)
                    except TranslationError:
                        continue
                    if not (pde & _PRESENT):
                        continue

                    va_pd = va_pdpt | (pd_idx << 21)

                    # 2MB large page
                    if pde & _PAGE_SIZE:
                        yield VirtualMapping(
                            virtual_start=va_pd,
                            physical_start=pde & _PHYS_ADDR_MASK_2M,
                            size=PAGE_2M,
                            writable=bool(
                                pml4e & _WRITABLE
                                and pdpte & _WRITABLE
                                and pde & _WRITABLE
                            ),
                            user=bool(
                                pml4e & _USER and pdpte & _USER and pde & _USER
                            ),
                            no_execute=bool(
                                pml4e & _NX or pdpte & _NX or pde & _NX
                            ),
                            level=2,
                        )
                        continue

                    pt_base = pde & _PHYS_ADDR_MASK_4K
                    for pt_idx in range(512):
                        try:
                            pte = self._read_entry(pt_base + pt_idx * 8)
                        except TranslationError:
                            continue
                        if not (pte & _PRESENT):
                            continue

                        va_pt = va_pd | (pt_idx << 12)
                        yield VirtualMapping(
                            virtual_start=va_pt,
                            physical_start=pte & _PHYS_ADDR_MASK_4K,
                            size=PAGE_4K,
                            writable=bool(
                                pml4e & _WRITABLE
                                and pdpte & _WRITABLE
                                and pde & _WRITABLE
                                and pte & _WRITABLE
                            ),
                            user=bool(
                                pml4e & _USER
                                and pdpte & _USER
                                and pde & _USER
                                and pte & _USER
                            ),
                            no_execute=bool(
                                pml4e & _NX
                                or pdpte & _NX
                                or pde & _NX
                                or pte & _NX
                            ),
                            level=1,
                        )

    def scan_for_cr3_candidates(
        self,
        *,
        min_mappings: int = 10,
        step: int = PAGE_4K,
    ) -> Iterator[int]:
        """Brute-force scan physical memory for plausible CR3 values.

        Checks each page-aligned physical address as a potential PML4 base.
        A candidate is emitted if it contains at least *min_mappings* present
        PML4 entries pointing to valid physical addresses within the layer.

        This is the fallback when OS kernel structures are unavailable.
        """
        max_addr = self._layer.maximum_address
        for addr in range(0, max_addr, step):
            if not self._layer.is_valid(addr, 8):
                continue
            present_count = 0
            for idx in range(512):
                try:
                    entry = self._read_entry(addr + idx * 8)
                except TranslationError:
                    break
                if entry & _PRESENT:
                    target = entry & _PHYS_ADDR_MASK_4K
                    if 0 < target < max_addr:
                        present_count += 1
            if present_count >= min_mappings:
                yield addr


def _sign_extend(value: int, bits: int) -> int:
    """Sign-extend a value from *bits* to 64 bits (canonical address form)."""
    sign_bit = 1 << (bits - 1)
    if value & sign_bit:
        return value | (~0 << bits)
    return value
