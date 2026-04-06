"""Hopper Disassembler-based reverse engineering engine."""
from __future__ import annotations

import json
import platform
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from deepview.core.exceptions import (
    AnalysisTimeoutError,
    DecompilationError,
    EngineNotAvailableError,
    ProjectError,
    ReverseEngineeringError,
)
from deepview.core.logging import get_logger
from deepview.interfaces.disassembler import DisassemblyEngine, DisassemblySession

if TYPE_CHECKING:
    from deepview.core.config import DisassemblyConfig

log = get_logger("disassembly.hopper")

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts" / "hopper"

# Common Hopper installation paths by platform.
_HOPPER_MACOS_PATHS = [
    "/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper",
    "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
]


class HopperEngine(DisassemblyEngine):
    """Disassembly engine backed by Hopper Disassembler."""

    def __init__(self, config: DisassemblyConfig | None = None) -> None:
        self._config = config
        self._cli_path: Path | None = None
        self._available = False
        self._detect()

    def _detect(self) -> None:
        """Locate the Hopper CLI binary."""
        import shutil

        # Check config path first
        if self._config and self._config.hopper_cli_path:
            candidate = Path(self._config.hopper_cli_path)
            if candidate.exists():
                self._cli_path = candidate
                self._available = True
                log.debug("hopper_found", path=str(candidate))
                return

        # Check PATH
        for name in ("hopper", "hopperv4"):
            found = shutil.which(name)
            if found:
                self._cli_path = Path(found)
                self._available = True
                log.debug("hopper_found_on_path", path=found)
                return

        # Check macOS application bundle
        if platform.system() == "Darwin":
            for mac_path in _HOPPER_MACOS_PATHS:
                if Path(mac_path).exists():
                    self._cli_path = Path(mac_path)
                    self._available = True
                    log.debug("hopper_found_macos", path=mac_path)
                    return

    def is_available(self) -> bool:
        return self._available

    @classmethod
    def engine_name(cls) -> str:
        return "Hopper"

    @classmethod
    def supported_capabilities(cls) -> set[str]:
        return {
            "disassemble", "decompile", "cfg",
            "functions", "strings", "signatures",
        }

    def open_binary(self, path: Path) -> HopperSession:
        if not self._available:
            raise EngineNotAvailableError("Hopper is not installed or not found")
        return HopperSession(path, cli_path=self._cli_path, config=self._config)


class HopperSession(DisassemblySession):
    """Analysis session backed by Hopper Disassembler."""

    def __init__(
        self,
        binary_path: Path,
        cli_path: Path | None,
        config: DisassemblyConfig | None,
    ) -> None:
        self._binary_path = binary_path
        self._cli_path = cli_path
        self._config = config
        self._cached_functions: list[dict[str, Any]] | None = None

    def _run_script(
        self,
        script_name: str,
        script_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a Hopper script on the binary and return parsed JSON."""
        from deepview.utils.process import run_command

        script_path = _SCRIPTS_DIR / script_name
        if not script_path.exists():
            raise ReverseEngineeringError(f"Hopper script not found: {script_path}")

        # Use a temp directory (not a bare temp file) to avoid TOCTOU races.
        with tempfile.TemporaryDirectory(prefix="deepview_hopper_") as tmpdir:
            output_path = Path(tmpdir) / "output.json"

            args = [
                str(self._cli_path),
                "--headless",
                "-e", str(self._binary_path),
                "--script", str(script_path),
                "--args", str(output_path),
            ]
            if script_args:
                args.extend(script_args)

            timeout = 300
            if self._config:
                timeout = self._config.ghidra_analysis_timeout  # reuse timeout

            try:
                result = run_command(args, timeout=timeout)
                if output_path.exists() and output_path.stat().st_size > 0:
                    return json.loads(output_path.read_text())
                if not result.success:
                    raise ReverseEngineeringError(
                        f"Hopper script '{script_name}' failed: {result.stderr[:500]}"
                    )
                return {}
            except TimeoutError:
                raise AnalysisTimeoutError("Hopper analysis timed out.")

    def disassemble(self, address: int, count: int = 20) -> list[dict[str, Any]]:
        data = self._run_script(
            "deepview_export.py",
            ["disassemble", f"0x{address:x}", str(count)],
        )
        return data.get("instructions", [])

    def disassemble_function(self, name_or_address: str | int) -> list[dict[str, Any]]:
        target = str(name_or_address)
        if isinstance(name_or_address, int):
            target = f"0x{name_or_address:x}"
        data = self._run_script(
            "deepview_export.py",
            ["disassemble_function", target],
        )
        return data.get("instructions", [])

    def decompile(self, name_or_address: str | int) -> str:
        target = str(name_or_address)
        if isinstance(name_or_address, int):
            target = f"0x{name_or_address:x}"
        data = self._run_script(
            "deepview_export.py",
            ["decompile", target],
        )
        source = data.get("source", "")
        if not source:
            raise DecompilationError(
                f"Hopper decompilation produced no output for '{name_or_address}'"
            )
        return source

    def functions(self) -> list[dict[str, Any]]:
        if self._cached_functions is not None:
            return self._cached_functions
        data = self._run_script("deepview_export.py", ["functions"])
        self._cached_functions = data.get("functions", [])
        return self._cached_functions

    def xrefs_to(self, address: int) -> list[dict[str, Any]]:
        raise ReverseEngineeringError(
            "Cross-reference analysis is not supported by Hopper CLI mode. "
            "Use Ghidra for xref analysis."
        )

    def xrefs_from(self, address: int) -> list[dict[str, Any]]:
        raise ReverseEngineeringError(
            "Cross-reference analysis is not supported by Hopper CLI mode. "
            "Use Ghidra for xref analysis."
        )

    def cfg(self, name_or_address: str | int) -> dict[str, Any]:
        target = str(name_or_address)
        if isinstance(name_or_address, int):
            target = f"0x{name_or_address:x}"
        return self._run_script("deepview_export.py", ["cfg", target])

    def strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        data = self._run_script(
            "deepview_export.py",
            ["strings", str(min_length)],
        )
        return data.get("strings", [])

    def close(self) -> None:
        self._cached_functions = None

    @property
    def binary_info(self) -> dict[str, Any]:
        return {
            "path": str(self._binary_path),
            "engine": "hopper",
        }
