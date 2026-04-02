"""Binary reassembly with embedded monitoring hooks."""
from __future__ import annotations
from pathlib import Path
from deepview.core.logging import get_logger
from deepview.core.exceptions import ReassemblyError
from deepview.interfaces.instrumentor import HookDefinition
from deepview.instrumentation.binary.analyzer import BinaryAnalyzer
from deepview.instrumentation.binary.points import InstrumentationPointFinder
from deepview.instrumentation.binary.patcher import BinaryPatcher
from deepview.instrumentation.binary.trampoline import TrampolineGenerator

log = get_logger("instrumentation.binary.reassembler")


class BinaryReassembler:
    """Orchestrates binary reassembly with embedded monitoring hooks.

    Pipeline:
    1. Parse binary with LIEF
    2. Discover instrumentation points
    3. Generate trampolines for each hook
    4. Add new section with trampolines
    5. Patch function prologues
    6. Write modified binary
    """

    def __init__(self, input_path: Path, output_path: Path):
        self._input = input_path
        self._output = output_path
        self._analyzer = BinaryAnalyzer(input_path)
        self._hooks: list[HookDefinition] = []

    def add_hook(self, hook: HookDefinition) -> None:
        self._hooks.append(hook)

    def add_hooks_for_security_sensitive(self) -> int:
        """Auto-add hooks for security-sensitive functions."""
        finder = InstrumentationPointFinder(self._analyzer)
        points = finder.find_security_sensitive()
        for pt in points:
            self._hooks.append(HookDefinition(
                hook_id=f"reassembly_{pt.name}",
                module="",
                function=pt.name,
                address=pt.address,
            ))
        return len(points)

    def add_hooks_for_exports(self) -> int:
        """Auto-add hooks for all exported functions."""
        finder = InstrumentationPointFinder(self._analyzer)
        points = finder.find_exports()
        for pt in points:
            self._hooks.append(HookDefinition(
                hook_id=f"reassembly_{pt.name}",
                module="",
                function=pt.name,
                address=pt.address,
            ))
        return len(points)

    def build(self) -> Path:
        """Execute the full reassembly pipeline."""
        if not self._hooks:
            raise ReassemblyError("No hooks defined")

        if not self._analyzer.is_available:
            raise ReassemblyError("LIEF is not available")

        patcher = BinaryPatcher(self._input)
        trampoline_gen = TrampolineGenerator(self._analyzer.arch)

        # Build trampoline section content
        trampoline_data = bytearray()
        hook_offsets: list[tuple[HookDefinition, int, bytes]] = []

        for hook in self._hooks:
            if hook.address is None or hook.address == 0:
                log.warning("skipping_hook", hook_id=hook.hook_id, reason="no address")
                continue

            try:
                code = self._analyzer.get_bytes_at(hook.address, 32)
                stolen, count = trampoline_gen.compute_stolen_bytes(code)

                tramp_offset = len(trampoline_data)
                # Placeholder trampoline (simplified - full impl needs relocation)
                trampoline = stolen + trampoline_gen.generate_jump(0, hook.address + len(stolen))
                trampoline_data.extend(trampoline)

                hook_offsets.append((hook, tramp_offset, stolen))

            except Exception as e:
                log.warning("trampoline_failed", hook_id=hook.hook_id, error=str(e))

        if not hook_offsets:
            raise ReassemblyError("No hooks could be generated")

        # Add the trampoline section
        section_base = patcher.add_section(".dvmon", bytes(trampoline_data))

        # Patch each function's prologue to jump to its trampoline
        for hook, tramp_offset, stolen in hook_offsets:
            tramp_addr = section_base + tramp_offset
            jump = trampoline_gen.generate_jump(hook.address, tramp_addr)
            patcher.patch_bytes(hook.address, jump)
            log.info("patched", function=hook.function, address=hex(hook.address))

        # Write output
        patcher.write(self._output)
        log.info("reassembly_complete",
                 output=str(self._output),
                 hooks=len(hook_offsets))

        return self._output
