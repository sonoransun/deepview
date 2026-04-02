"""VM state extraction and parsing."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from deepview.core.logging import get_logger

log = get_logger("vm.state")


@dataclass
class CPUState:
    """CPU register state from a VM snapshot."""
    rax: int = 0
    rbx: int = 0
    rcx: int = 0
    rdx: int = 0
    rsi: int = 0
    rdi: int = 0
    rsp: int = 0
    rbp: int = 0
    rip: int = 0
    rflags: int = 0
    cr0: int = 0
    cr3: int = 0
    cr4: int = 0


@dataclass
class VMState:
    """Complete VM state from a snapshot."""
    cpu: CPUState = field(default_factory=CPUState)
    memory_size: int = 0
    num_cpus: int = 1
    metadata: dict = field(default_factory=dict)


def extract_state_from_corefile(path: Path) -> VMState:
    """Extract VM state from an ELF core dump (as produced by virsh dump)."""
    from deepview.memory.formats.elf_core import ELFCoreLayer

    layer = ELFCoreLayer(path)
    state = VMState(
        memory_size=layer.maximum_address,
    )
    layer.close()

    log.info("state_extracted", path=str(path), memory_size=state.memory_size)
    return state
