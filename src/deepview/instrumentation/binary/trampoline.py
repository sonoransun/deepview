"""Architecture-specific trampoline code generation."""
from __future__ import annotations
import struct
from deepview.core.logging import get_logger
from deepview.core.exceptions import DisassemblyError, RelocationError

log = get_logger("instrumentation.binary.trampoline")


class TrampolineGenerator:
    """Generate trampoline/detour code for function hooking."""

    def __init__(self, arch: str = "x86_64"):
        self._arch = arch
        self._cs = None
        try:
            import capstone
            if arch == "x86_64":
                self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif arch == "aarch64":
                self._cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif arch == "x86":
                self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            if self._cs:
                self._cs.detail = True
        except ImportError:
            log.debug("capstone_not_installed")

    def compute_stolen_bytes(self, code: bytes, min_size: int = 5) -> tuple[bytes, int]:
        """Determine minimum complete instructions >= min_size bytes.

        Returns (stolen_bytes, instruction_count).
        """
        if not self._cs:
            raise DisassemblyError("Capstone is not installed")

        total = 0
        count = 0
        for insn in self._cs.disasm(code, 0):
            total += insn.size
            count += 1
            if total >= min_size:
                break

        if total < min_size:
            raise DisassemblyError(f"Could not find {min_size} bytes of complete instructions")

        return code[:total], count

    def generate_jump(self, from_addr: int, to_addr: int) -> bytes:
        """Generate a jump instruction from one address to another."""
        if self._arch in ("x86_64", "x86"):
            # Try relative JMP (5 bytes) first
            offset = to_addr - (from_addr + 5)
            if -2**31 <= offset < 2**31:
                return b"\xe9" + struct.pack("<i", offset)

            # Absolute JMP via register (14 bytes for x86_64)
            if self._arch == "x86_64":
                return (
                    b"\x49\xbb" + struct.pack("<Q", to_addr) +  # mov r11, addr
                    b"\x41\xff\xe3"                              # jmp r11
                )
            else:
                return b"\xe9" + struct.pack("<i", offset)  # 32-bit always fits

        elif self._arch == "aarch64":
            offset = to_addr - from_addr
            if -(1 << 27) <= offset < (1 << 27):
                # B instruction (26-bit signed offset, shifted left 2)
                imm26 = (offset >> 2) & 0x3FFFFFF
                return struct.pack("<I", 0x14000000 | imm26)

            # Full 64-bit branch sequence (16 bytes)
            return (
                struct.pack("<I", 0xD2800010 | ((to_addr & 0xFFFF) << 5)) +           # MOVZ X16, #imm16
                struct.pack("<I", 0xF2A00010 | (((to_addr >> 16) & 0xFFFF) << 5)) +   # MOVK X16, #imm16, LSL #16
                struct.pack("<I", 0xF2C00010 | (((to_addr >> 32) & 0xFFFF) << 5)) +   # MOVK X16, #imm16, LSL #32
                struct.pack("<I", 0xD61F0200)                                           # BR X16
            )

        raise DisassemblyError(f"Unsupported architecture: {self._arch}")

    def generate_trampoline(self, target_addr: int, stolen_bytes: bytes,
                            hook_addr: int, return_addr: int) -> bytes:
        """Generate a full trampoline that calls hook, executes stolen bytes, then returns."""
        parts = bytearray()

        if self._arch == "x86_64":
            # Save registers
            parts.extend(b"\x50")           # push rax
            parts.extend(b"\x51")           # push rcx
            parts.extend(b"\x52")           # push rdx
            parts.extend(b"\x56")           # push rsi
            parts.extend(b"\x57")           # push rdi
            parts.extend(b"\x41\x50")       # push r8
            parts.extend(b"\x41\x51")       # push r9
            parts.extend(b"\x41\x52")       # push r10
            parts.extend(b"\x41\x53")       # push r11
            parts.extend(b"\x9c")           # pushfq

            # Call hook function
            parts.extend(b"\x48\xb8" + struct.pack("<Q", hook_addr))  # mov rax, hook_addr
            parts.extend(b"\xff\xd0")                                   # call rax

            # Restore registers
            parts.extend(b"\x9d")           # popfq
            parts.extend(b"\x41\x5b")       # pop r11
            parts.extend(b"\x41\x5a")       # pop r10
            parts.extend(b"\x41\x59")       # pop r9
            parts.extend(b"\x41\x58")       # pop r8
            parts.extend(b"\x5f")           # pop rdi
            parts.extend(b"\x5e")           # pop rsi
            parts.extend(b"\x5a")           # pop rdx
            parts.extend(b"\x59")           # pop rcx
            parts.extend(b"\x58")           # pop rax

            # Execute stolen bytes
            parts.extend(stolen_bytes)

            # Jump back to original function (after stolen bytes)
            jmp_back = self.generate_jump(0, return_addr)  # Placeholder address
            parts.extend(jmp_back)

        return bytes(parts)
