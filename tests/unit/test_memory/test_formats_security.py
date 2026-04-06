"""Security tests for memory format parsers — malformed inputs."""
from __future__ import annotations

import struct
import pytest

from deepview.core.exceptions import FormatError
from deepview.memory.formats.lime_format import LiMEMemoryLayer, LIME_MAGIC, LIME_HEADER_FMT
from deepview.memory.formats.elf_core import ELFCoreLayer


class TestLiMEMalformed:
    def _make_lime_header(self, start: int, end: int, version: int = 1) -> bytes:
        return struct.pack(LIME_HEADER_FMT, LIME_MAGIC, version, start, end, 0)

    def test_end_less_than_start_raises(self, tmp_path):
        """Range with end < start must be rejected."""
        f = tmp_path / "bad_range.lime"
        header = self._make_lime_header(start=0x2000, end=0x1000)
        f.write_bytes(header)
        with pytest.raises(FormatError, match="end.*< start"):
            LiMEMemoryLayer(f)

    def test_range_exceeds_file_size_raises(self, tmp_path):
        """Range claiming more data than the file contains must be rejected."""
        f = tmp_path / "short.lime"
        header = self._make_lime_header(start=0, end=0xFFFF)  # claims 64KB
        f.write_bytes(header + b"\x00" * 10)  # only 10 bytes of data
        with pytest.raises(FormatError, match="extends past end"):
            LiMEMemoryLayer(f)

    def test_huge_range_rejected(self, tmp_path):
        """Range larger than _MAX_RANGE_SIZE must be rejected."""
        f = tmp_path / "huge.lime"
        # Claim 2 TB range (exceeds 1 TB limit)
        header = self._make_lime_header(start=0, end=(2 << 40) - 1)
        f.write_bytes(header)
        with pytest.raises(FormatError, match="too large"):
            LiMEMemoryLayer(f)

    def test_truncated_header_no_crash(self, tmp_path):
        """File shorter than a full header should not crash."""
        f = tmp_path / "truncated.lime"
        f.write_bytes(b"\x45\x4d\x69\x4c")  # Just magic bytes
        with pytest.raises(FormatError, match="No valid"):
            LiMEMemoryLayer(f)

    def test_empty_file_raises(self, tmp_path):
        """Empty file must raise FormatError, not crash."""
        f = tmp_path / "empty.lime"
        f.write_bytes(b"")
        with pytest.raises(FormatError, match="No valid"):
            LiMEMemoryLayer(f)


class TestELFCoreMalformed:
    def test_not_elf_raises(self, tmp_path):
        f = tmp_path / "notelf.core"
        f.write_bytes(b"NOT AN ELF FILE AT ALL" + b"\x00" * 100)
        with pytest.raises(FormatError, match="Not a valid ELF"):
            ELFCoreLayer(f)

    def test_truncated_elf_header_raises(self, tmp_path):
        f = tmp_path / "truncated.core"
        # Full 16-byte ident (64-bit, little-endian) but truncated main header
        ident = b"\x7fELF\x02\x01" + b"\x00" * 10
        f.write_bytes(ident + b"\x00" * 10)  # Only 10 bytes of header (need 48)
        with pytest.raises(FormatError, match="Truncated"):
            ELFCoreLayer(f)

    def test_32bit_elf_rejected(self, tmp_path):
        f = tmp_path / "elf32.core"
        ident = b"\x7fELF\x01" + b"\x00" * 11  # class=1 (32-bit)
        f.write_bytes(ident + b"\x00" * 100)
        with pytest.raises(FormatError, match="64-bit"):
            ELFCoreLayer(f)

    def test_phdr_past_file_raises(self, tmp_path):
        """Program header table pointing past EOF must be rejected."""
        f = tmp_path / "bad_phoff.core"
        ident = b"\x7fELF\x02\x01" + b"\x00" * 10  # 64-bit, little-endian
        # Build header with e_phoff pointing way past file
        hdr = struct.pack("<HHI", 4, 0, 1)  # e_type=4(core), e_machine, e_version
        hdr += b"\x00" * 8  # e_entry
        hdr += struct.pack("<Q", 0xFFFF0000)  # e_phoff = very large
        hdr += b"\x00" * 4  # e_shoff low
        hdr += b"\x00" * 4  # e_flags
        hdr += struct.pack("<H", 64)  # e_ehsize
        hdr += struct.pack("<H", 56)  # e_phentsize
        hdr += struct.pack("<H", 1)   # e_phnum
        hdr = hdr[:48]  # Truncate to expected size
        f.write_bytes(ident + hdr + b"\x00" * 100)
        with pytest.raises(FormatError, match="past end of file"):
            ELFCoreLayer(f)

    def test_segment_past_file_raises(self, tmp_path):
        """PT_LOAD segment extending past EOF must be rejected."""
        f = tmp_path / "bad_segment.core"
        ident = b"\x7fELF\x02\x01" + b"\x00" * 10
        # ELF header: phoff=64, phentsize=56, phnum=1
        hdr = bytearray(48)
        struct.pack_into("<Q", hdr, 16, 64)    # e_phoff
        struct.pack_into("<H", hdr, 34, 56)    # e_phentsize
        struct.pack_into("<H", hdr, 36, 1)     # e_phnum
        # Program header: type=PT_LOAD, offset=0, filesz=very large
        phdr = bytearray(56)
        struct.pack_into("<I", phdr, 0, 1)     # p_type = PT_LOAD
        struct.pack_into("<Q", phdr, 8, 200)   # p_offset (past file)
        struct.pack_into("<Q", phdr, 32, 0x100000)  # p_filesz
        f.write_bytes(ident + bytes(hdr) + bytes(phdr))
        with pytest.raises(FormatError, match="extends past file"):
            ELFCoreLayer(f)
