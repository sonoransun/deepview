"""Binary patching engine using LIEF."""
from __future__ import annotations
from pathlib import Path
from deepview.core.logging import get_logger
from deepview.core.exceptions import PatchError

log = get_logger("instrumentation.binary.patcher")


class BinaryPatcher:
    """Apply patches to PE/ELF/Mach-O binaries via LIEF."""

    def __init__(self, path: Path):
        self._path = path
        try:
            import lief
            self._lief = lief
            self._binary = lief.parse(str(path))
            if self._binary is None:
                raise PatchError(f"Failed to parse: {path}")
        except ImportError:
            raise PatchError("LIEF is not installed")

    def add_section(self, name: str, content: bytes, executable: bool = True) -> int:
        """Add a new section to the binary. Returns its virtual address."""
        section = self._lief.Section(name)
        section.content = list(content)
        if executable:
            # Set appropriate flags based on format
            if hasattr(self._binary, 'add'):
                added = self._binary.add(section)
            else:
                added = self._binary.add_section(section)
            log.info("section_added", name=name, size=len(content))
            return added.virtual_address if hasattr(added, 'virtual_address') else 0
        return 0

    def patch_bytes(self, virtual_address: int, new_bytes: bytes) -> None:
        """Overwrite bytes at a virtual address."""
        self._binary.patch_address(virtual_address, list(new_bytes))

    def write(self, output: Path) -> None:
        """Write the modified binary."""
        self._binary.write(str(output))
        log.info("binary_written", output=str(output))
