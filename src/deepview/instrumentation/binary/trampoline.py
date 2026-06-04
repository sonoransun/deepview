"""Architecture-specific trampoline code generation."""
from __future__ import annotations
import struct
from deepview.core.logging import get_logger
from deepview.core.exceptions import DisassemblyError

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
                            hook_addr: int, return_addr: int,
                            base_addr: int = 0) -> bytes:
        """Generate a full trampoline that calls hook, executes stolen bytes, then returns.

        Args:
            target_addr: Address of the original function being hooked.
            stolen_bytes: Instructions copied from the original function prologue.
            hook_addr: Address of the hook function to call.
            return_addr: Address to jump back to after executing stolen bytes.
            base_addr: Address where the trampoline will be loaded. Required for
                correct relative jump calculation.
        """
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
            jmp_from = base_addr + len(parts)
            jmp_back = self.generate_jump(jmp_from, return_addr)
            parts.extend(jmp_back)

        elif self._arch == "aarch64":
            # Save caller-saved registers via STP pairs onto a sub'd stack.
            # We preserve X0..X17 (the argument/temporary registers the hook
            # may clobber) plus X29/X30 (frame pointer + link register, since
            # we issue a BLR). 10 pairs * 16 bytes = 160 bytes of stack space.
            #
            # STP encoding (pre-index, 64-bit): 1010 1001 10 imm7 Rt2 Rn Rt
            #   base = 0xA9800000 (STP <Xt1>, <Xt2>, [SP, #imm]!)
            # imm7 is the offset scaled by 8 (signed). For the first pair we
            # pre-decrement SP by -160 (imm7 = -20 = 0x6C in 7-bit two's-comp);
            # subsequent pairs store at positive scaled offsets without writeback.
            #
            # LDP encoding (post-index / offset, 64-bit):
            #   base = 0xA9400000 (LDP <Xt1>, <Xt2>, [SP, #imm])
            def _stp(rt1: int, rt2: int, imm7: int, writeback: bool) -> int:
                base = 0xA9800000 if writeback else 0xA9000000
                return base | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (31 << 5) | rt1

            def _ldp(rt1: int, rt2: int, imm7: int, writeback: bool) -> int:
                base = 0xA8C00000 if writeback else 0xA9400000
                return base | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (31 << 5) | rt1

            reg_pairs = [
                (0, 1), (2, 3), (4, 5), (6, 7), (8, 9),
                (10, 11), (12, 13), (14, 15), (16, 17), (29, 30),
            ]
            frame = len(reg_pairs) * 16  # 160 bytes

            # First STP pre-decrements SP by the whole frame (imm7 = -frame/8).
            parts.extend(struct.pack("<I", _stp(0, 1, -(frame // 8), writeback=True)))
            # Remaining pairs store at positive scaled offsets (slot * 2 in regs).
            for i, (rt1, rt2) in enumerate(reg_pairs[1:], start=1):
                parts.extend(struct.pack("<I", _stp(rt1, rt2, i * 2, writeback=False)))

            # Load the 64-bit hook address into X16 via MOVZ/MOVK x4.
            #   MOVZ X16, #imm16          base = 0xD2800010
            #   MOVK X16, #imm16, LSL #16 base = 0xF2A00010
            #   MOVK X16, #imm16, LSL #32 base = 0xF2C00010
            #   MOVK X16, #imm16, LSL #48 base = 0xF2E00010
            parts.extend(struct.pack("<I", 0xD2800010 | ((hook_addr & 0xFFFF) << 5)))
            parts.extend(struct.pack("<I", 0xF2A00010 | (((hook_addr >> 16) & 0xFFFF) << 5)))
            parts.extend(struct.pack("<I", 0xF2C00010 | (((hook_addr >> 32) & 0xFFFF) << 5)))
            parts.extend(struct.pack("<I", 0xF2E00010 | (((hook_addr >> 48) & 0xFFFF) << 5)))

            # BLR X16 -> call the hook (sets X30 = return).
            parts.extend(struct.pack("<I", 0xD63F0200))

            # Restore registers (reverse order; final LDP post-increments SP).
            for i, (rt1, rt2) in enumerate(reg_pairs[1:], start=1):
                parts.extend(struct.pack("<I", _ldp(rt1, rt2, i * 2, writeback=False)))
            parts.extend(struct.pack("<I", _ldp(0, 1, frame // 8, writeback=True)))

            # Execute stolen bytes verbatim.
            parts.extend(stolen_bytes)

            # Jump back to original function (after stolen bytes).
            jmp_from = base_addr + len(parts)
            jmp_back = self.generate_jump(jmp_from, return_addr)
            parts.extend(jmp_back)

        elif self._arch == "x86":
            # Save general-purpose registers and flags.
            parts.extend(b"\x60")           # pushad
            parts.extend(b"\x9c")           # pushfd

            # Call hook function.
            parts.extend(b"\xb8" + struct.pack("<I", hook_addr))  # mov eax, hook_addr
            parts.extend(b"\xff\xd0")                              # call eax

            # Restore flags and registers.
            parts.extend(b"\x9d")           # popfd
            parts.extend(b"\x61")           # popad

            # Execute stolen bytes.
            parts.extend(stolen_bytes)

            # Jump back to original function (after stolen bytes).
            jmp_from = base_addr + len(parts)
            jmp_back = self.generate_jump(jmp_from, return_addr)
            parts.extend(jmp_back)

        return bytes(parts)
