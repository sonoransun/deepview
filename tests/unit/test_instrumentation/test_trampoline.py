"""Tests for trampoline code generation."""
from __future__ import annotations

import struct

import pytest

from deepview.core.exceptions import DisassemblyError
from deepview.instrumentation.binary.trampoline import TrampolineGenerator


class TestGenerateJumpX86_64:
    """Test jump generation for x86_64 architecture."""

    def test_generate_jump_x86_64_relative(self):
        gen = TrampolineGenerator(arch="x86_64")
        result = gen.generate_jump(0x1000, 0x2000)

        # Relative JMP: 0xE9 + 4-byte signed LE offset
        assert len(result) == 5
        assert result[0:1] == b"\xe9"
        expected_offset = 0x2000 - (0x1000 + 5)  # 0x0FFB
        assert struct.unpack("<i", result[1:])[0] == expected_offset

    def test_generate_jump_x86_64_absolute(self):
        gen = TrampolineGenerator(arch="x86_64")
        # Far address that won't fit in a 32-bit relative offset
        result = gen.generate_jump(0, 0x7FFFFFFFFFFF)

        # mov r11, imm64 (2 bytes) + addr (8 bytes) + jmp r11 (3 bytes) = 13
        assert len(result) == 13
        # mov r11, imm64
        assert result[:2] == b"\x49\xbb"
        # Encoded target address
        addr = struct.unpack("<Q", result[2:10])[0]
        assert addr == 0x7FFFFFFFFFFF
        # jmp r11
        assert result[10:] == b"\x41\xff\xe3"


class TestGenerateJumpX86:
    """Test jump generation for 32-bit x86 architecture."""

    def test_generate_jump_x86_relative(self):
        gen = TrampolineGenerator(arch="x86")
        result = gen.generate_jump(0x1000, 0x2000)

        assert len(result) == 5
        assert result[0:1] == b"\xe9"
        expected_offset = 0x2000 - (0x1000 + 5)
        assert struct.unpack("<i", result[1:])[0] == expected_offset


class TestGenerateJumpAarch64:
    """Test jump generation for AArch64 architecture."""

    def test_generate_jump_aarch64_relative(self):
        gen = TrampolineGenerator(arch="aarch64")
        result = gen.generate_jump(0x1000, 0x1100)

        # B instruction: 4 bytes
        assert len(result) == 4
        insn = struct.unpack("<I", result)[0]
        # Top 6 bits should be 000101 for B instruction
        assert (insn >> 26) == 0b000101

    def test_generate_jump_aarch64_absolute(self):
        gen = TrampolineGenerator(arch="aarch64")
        # Far address beyond 26-bit offset range
        result = gen.generate_jump(0, 0xFFFF_FFFF_FFFF)

        # MOVZ + MOVK + MOVK + BR = 16 bytes
        assert len(result) == 16


class TestGenerateJumpUnsupported:
    """Test unsupported architecture raises DisassemblyError."""

    def test_generate_jump_unsupported_arch(self):
        gen = TrampolineGenerator(arch="mips")
        with pytest.raises(DisassemblyError, match="Unsupported architecture"):
            gen.generate_jump(0x1000, 0x2000)


class TestGenerateTrampoline:
    """Test full trampoline generation for x86_64."""

    def test_generate_trampoline_x86_64(self):
        gen = TrampolineGenerator(arch="x86_64")
        stolen = b"\x55\x48\x89\xe5\x90"  # push rbp; mov rbp, rsp; nop (5 bytes)
        result = gen.generate_trampoline(
            target_addr=0x4000,
            stolen_bytes=stolen,
            hook_addr=0x6000,
            return_addr=0x4005,
            base_addr=0x5000,
        )

        assert isinstance(result, bytes)
        assert len(result) > 0
        # The stolen bytes should appear in the trampoline
        assert stolen in result
        # The final jump should use base_addr + offset as from_addr,
        # so verify the last part contains a jump instruction (0xE9 or absolute)
        # Find the stolen bytes position, the jump is right after
        stolen_pos = result.index(stolen)
        after_stolen = result[stolen_pos + len(stolen):]
        assert len(after_stolen) > 0  # There must be a jump after stolen bytes

    def test_generate_trampoline_base_addr_matters(self):
        gen = TrampolineGenerator(arch="x86_64")
        stolen = b"\x55\x48\x89\xe5\x90"

        result_a = gen.generate_trampoline(
            target_addr=0x4000,
            stolen_bytes=stolen,
            hook_addr=0x6000,
            return_addr=0x4005,
            base_addr=0,
        )

        result_b = gen.generate_trampoline(
            target_addr=0x4000,
            stolen_bytes=stolen,
            hook_addr=0x6000,
            return_addr=0x4005,
            base_addr=0x10000,
        )

        # Different base_addr should produce different jump offsets
        assert result_a != result_b
