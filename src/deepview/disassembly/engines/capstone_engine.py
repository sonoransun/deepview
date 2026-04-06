"""Capstone-based lightweight disassembly engine (fallback)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from deepview.core.exceptions import ReverseEngineeringError
from deepview.core.logging import get_logger
from deepview.interfaces.disassembler import DisassemblyEngine, DisassemblySession

log = get_logger("disassembly.capstone")

# Architecture constants (Capstone values)
_ARCH_MAP: dict[str, tuple[int, int]] = {}  # populated lazily


def _populate_arch_map() -> None:
    """Fill _ARCH_MAP from capstone constants (called after import)."""
    import capstone  # noqa: WPS433

    _ARCH_MAP.update({
        "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "aarch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    })


class CapstoneEngine(DisassemblyEngine):
    """Lightweight disassembly-only engine using Capstone."""

    def __init__(self) -> None:
        self._available = False
        self._capstone: Any = None
        try:
            import capstone  # noqa: WPS433

            self._capstone = capstone
            self._available = True
            if not _ARCH_MAP:
                _populate_arch_map()
            log.debug("capstone_loaded", version=capstone.cs_version())
        except ImportError:
            log.debug("capstone_not_installed")

    def is_available(self) -> bool:
        return self._available

    @classmethod
    def engine_name(cls) -> str:
        return "Capstone"

    @classmethod
    def supported_capabilities(cls) -> set[str]:
        return {"disassemble", "strings"}

    def open_binary(self, path: Path) -> CapstoneSession:
        if not self._available:
            raise ReverseEngineeringError("Capstone is not installed")
        return CapstoneSession(path, self._capstone)


class CapstoneSession(DisassemblySession):
    """Disassembly session backed by Capstone."""

    def __init__(self, path: Path, capstone: Any) -> None:
        self._path = path
        self._capstone = capstone
        self._data = path.read_bytes()
        self._arch = "x86_64"
        self._entry_point = 0
        self._sections: list[dict[str, Any]] = []
        self._detect_binary_info()

    def _detect_binary_info(self) -> None:
        """Use LIEF if available to extract binary metadata, else assume raw."""
        try:
            import lief  # noqa: WPS433

            binary = lief.parse(str(self._path))
            if binary is None:
                return
            if hasattr(binary, "header"):
                machine = getattr(binary.header, "machine_type", None)
                if machine is not None:
                    name = machine.name if hasattr(machine, "name") else str(machine)
                    if "AARCH64" in name or "ARM64" in name:
                        self._arch = "aarch64"
                    elif "386" in name or "I386" in name:
                        self._arch = "x86"
                    else:
                        self._arch = "x86_64"
            if hasattr(binary, "entrypoint"):
                self._entry_point = binary.entrypoint
            for sec in getattr(binary, "sections", []):
                self._sections.append({
                    "name": sec.name,
                    "virtual_address": sec.virtual_address,
                    "size": sec.size,
                })
        except ImportError:
            log.debug("lief_not_available_for_metadata")
        except Exception:
            log.debug("binary_parse_failed", path=str(self._path))

    def _make_md(self, arch: str | None = None) -> Any:
        """Create a Capstone disassembler for the session's architecture."""
        target = arch or self._arch
        if target not in _ARCH_MAP:
            raise ReverseEngineeringError(f"Unsupported architecture: {target}")
        cs_arch, cs_mode = _ARCH_MAP[target]
        md = self._capstone.Cs(cs_arch, cs_mode)
        md.detail = True
        return md

    def disassemble(self, address: int, count: int = 20) -> list[dict[str, Any]]:
        md = self._make_md()
        # Attempt to read bytes at the given offset within the binary data.
        # For raw files, address is an offset; for parsed binaries, we
        # need the section-relative offset.
        offset = self._resolve_offset(address)
        chunk = self._data[offset : offset + count * 15]  # generous upper bound
        result: list[dict[str, Any]] = []
        for insn in md.disasm(chunk, address):
            result.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes_hex": insn.bytes.hex(),
                "size": insn.size,
            })
            if len(result) >= count:
                break
        return result

    def disassemble_function(self, name_or_address: str | int) -> list[dict[str, Any]]:
        address = self._resolve_target(name_or_address)
        # Without function boundary info, disassemble a generous window.
        return self.disassemble(address, count=200)

    def decompile(self, name_or_address: str | int) -> str:
        raise ReverseEngineeringError(
            "Decompilation requires Ghidra or Hopper. "
            "Capstone only supports raw disassembly."
        )

    def functions(self) -> list[dict[str, Any]]:
        # Basic prologue-pattern matching (very limited accuracy).
        md = self._make_md()
        results: list[dict[str, Any]] = []
        # Scan for common function prologues
        push_rbp = b"\x55\x48\x89\xe5"  # push rbp; mov rbp, rsp
        idx = 0
        while True:
            idx = self._data.find(push_rbp, idx)
            if idx == -1:
                break
            results.append({
                "name": f"sub_{idx:x}",
                "address": idx,
                "size": 0,
            })
            idx += 1
        return results

    def xrefs_to(self, address: int) -> list[dict[str, Any]]:
        raise ReverseEngineeringError(
            "Cross-reference analysis requires Ghidra or Hopper."
        )

    def xrefs_from(self, address: int) -> list[dict[str, Any]]:
        raise ReverseEngineeringError(
            "Cross-reference analysis requires Ghidra or Hopper."
        )

    def cfg(self, name_or_address: str | int) -> dict[str, Any]:
        raise ReverseEngineeringError(
            "Control-flow graph analysis requires Ghidra or Hopper."
        )

    def strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        current: list[int] = []
        start = 0
        for i, b in enumerate(self._data):
            if 0x20 <= b <= 0x7E:
                if not current:
                    start = i
                current.append(b)
            else:
                if len(current) >= min_length:
                    results.append({
                        "address": start,
                        "value": bytes(current).decode("ascii"),
                        "encoding": "ascii",
                    })
                current = []
        if len(current) >= min_length:
            results.append({
                "address": start,
                "value": bytes(current).decode("ascii"),
                "encoding": "ascii",
            })
        return results

    def close(self) -> None:
        self._data = b""

    @property
    def binary_info(self) -> dict[str, Any]:
        return {
            "path": str(self._path),
            "arch": self._arch,
            "entry_point": self._entry_point,
            "size": len(self._data),
            "sections": self._sections,
        }

    def _resolve_offset(self, address: int) -> int:
        """Convert a virtual address to a file offset. Falls back to identity."""
        for sec in self._sections:
            va = sec["virtual_address"]
            size = sec["size"]
            if va <= address < va + size:
                return address - va
        return min(address, max(len(self._data) - 1, 0))

    def _resolve_target(self, name_or_address: str | int) -> int:
        """Resolve a function name or hex address to an integer address."""
        if isinstance(name_or_address, int):
            return name_or_address
        try:
            return int(name_or_address, 16)
        except ValueError:
            pass
        # Try to find the name in prologue-detected functions.
        for func in self.functions():
            if func["name"] == name_or_address:
                return func["address"]
        raise ReverseEngineeringError(
            f"Cannot resolve '{name_or_address}'. Capstone cannot resolve "
            "function names. Use a hex address or install Ghidra/Hopper."
        )
