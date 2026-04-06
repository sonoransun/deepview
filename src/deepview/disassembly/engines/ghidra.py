"""Ghidra-based disassembly and decompilation engine."""
from __future__ import annotations

import json
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

log = get_logger("disassembly.ghidra")

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts" / "ghidra"


class GhidraEngine(DisassemblyEngine):
    """Disassembly engine backed by Ghidra headless analyzer."""

    def __init__(self, config: DisassemblyConfig | None = None) -> None:
        self._config = config
        self._headless_path: Path | None = None
        self._pyhidra: Any = None
        self._available = False
        self._detect()

    def _detect(self) -> None:
        """Locate the Ghidra headless analyzer."""
        import shutil

        # Check config path first
        if self._config and self._config.ghidra_install_dir:
            candidate = Path(self._config.ghidra_install_dir) / "support" / "analyzeHeadless"
            if candidate.exists():
                self._headless_path = candidate
                self._available = True
                log.debug("ghidra_found", path=str(candidate))

        # Check PATH
        if not self._available:
            for name in ("analyzeHeadless", "analyzeHeadless.bat"):
                found = shutil.which(name)
                if found:
                    self._headless_path = Path(found)
                    self._available = True
                    log.debug("ghidra_found_on_path", path=found)
                    break

        # Optionally detect pyhidra for direct API access
        try:
            import pyhidra  # noqa: WPS433

            self._pyhidra = pyhidra
            log.debug("pyhidra_available")
        except ImportError:
            pass

    def is_available(self) -> bool:
        return self._available

    @classmethod
    def engine_name(cls) -> str:
        return "Ghidra"

    @classmethod
    def supported_capabilities(cls) -> set[str]:
        return {
            "disassemble", "decompile", "cfg", "xrefs",
            "functions", "strings", "data_types", "signatures",
        }

    def open_binary(self, path: Path) -> GhidraSession:
        if not self._available:
            raise EngineNotAvailableError("Ghidra is not installed or not found")
        return GhidraSession(
            path,
            headless_path=self._headless_path,
            config=self._config,
            pyhidra=self._pyhidra,
        )


class GhidraSession(DisassemblySession):
    """Analysis session backed by Ghidra headless analyzer or pyhidra."""

    def __init__(
        self,
        binary_path: Path,
        headless_path: Path | None,
        config: DisassemblyConfig | None,
        pyhidra: Any = None,
    ) -> None:
        self._binary_path = binary_path
        self._headless_path = headless_path
        self._config = config
        self._pyhidra = pyhidra
        self._project_dir: Path | None = None
        self._project_name = f"deepview_{binary_path.stem}"
        self._analyzed = False
        self._cached_functions: list[dict[str, Any]] | None = None

    def _ensure_analyzed(self) -> None:
        """Run headless analysis if not already done."""
        if self._analyzed:
            return
        self._run_headless_import()
        self._analyzed = True

    def _get_project_dir(self) -> Path:
        """Return the Ghidra project directory, creating if needed."""
        if self._project_dir:
            return self._project_dir
        if self._config and self._config.ghidra_project_dir:
            self._project_dir = Path(self._config.ghidra_project_dir)
        else:
            from platformdirs import user_cache_dir

            self._project_dir = Path(user_cache_dir("deepview")) / "ghidra_projects"
        self._project_dir.mkdir(parents=True, exist_ok=True)
        return self._project_dir

    def _run_headless_import(self) -> None:
        """Import and analyze the binary with Ghidra headless."""
        from deepview.utils.process import run_command

        project_dir = self._get_project_dir()
        args = [
            str(self._headless_path),
            str(project_dir),
            self._project_name,
            "-import", str(self._binary_path),
            "-overwrite",
        ]
        if self._config and self._config.ghidra_jvm_args:
            for jvm_arg in self._config.ghidra_jvm_args:
                args.insert(1, jvm_arg)

        timeout = 600
        if self._config:
            timeout = self._config.ghidra_analysis_timeout

        log.info("ghidra_headless_import", binary=str(self._binary_path))
        try:
            result = run_command(args, timeout=timeout)
            if not result.success:
                raise ProjectError(
                    f"Ghidra headless import failed: {result.stderr[:500]}"
                )
        except TimeoutError:
            raise AnalysisTimeoutError(
                f"Ghidra analysis timed out after {timeout}s. "
                "Increase ghidra_analysis_timeout in config."
            )

    def _run_script(self, script_name: str, script_args: list[str] | None = None) -> dict[str, Any]:
        """Run a Ghidra postScript and return parsed JSON output."""
        from deepview.utils.process import run_command

        self._ensure_analyzed()
        script_path = _SCRIPTS_DIR / script_name
        if not script_path.exists():
            raise ReverseEngineeringError(f"Ghidra script not found: {script_path}")

        # Use a temp directory (not a bare temp file) to avoid TOCTOU races.
        with tempfile.TemporaryDirectory(prefix="deepview_ghidra_") as tmpdir:
            output_path = Path(tmpdir) / "output.json"

            project_dir = self._get_project_dir()
            args = [
                str(self._headless_path),
                str(project_dir),
                self._project_name,
                "-process", self._binary_path.name,
                "-noanalysis",
                "-scriptPath", str(_SCRIPTS_DIR),
                "-postScript", script_name, str(output_path),
            ]
            if script_args:
                args.extend(script_args)

            timeout = 300
            if self._config:
                timeout = self._config.ghidra_analysis_timeout

            result = run_command(args, timeout=timeout)
            if output_path.exists():
                data = json.loads(output_path.read_text())
                return data
            if not result.success:
                raise ReverseEngineeringError(
                    f"Ghidra script '{script_name}' failed: {result.stderr[:500]}"
                )
            return {}

    def disassemble(self, address: int, count: int = 20) -> list[dict[str, Any]]:
        data = self._run_script(
            "export_disassembly.py",
            [f"0x{address:x}", str(count)],
        )
        return data.get("instructions", [])

    def disassemble_function(self, name_or_address: str | int) -> list[dict[str, Any]]:
        target = str(name_or_address)
        if isinstance(name_or_address, int):
            target = f"0x{name_or_address:x}"
        data = self._run_script("export_disassembly.py", [target, "0"])
        return data.get("instructions", [])

    def decompile(self, name_or_address: str | int) -> str:
        target = str(name_or_address)
        if isinstance(name_or_address, int):
            target = f"0x{name_or_address:x}"
        data = self._run_script("export_decompile.py", [target])
        source = data.get("source", "")
        if not source:
            raise DecompilationError(
                f"Decompilation produced no output for '{name_or_address}'"
            )
        return source

    def functions(self) -> list[dict[str, Any]]:
        if self._cached_functions is not None:
            return self._cached_functions
        data = self._run_script("export_functions.py")
        self._cached_functions = data.get("functions", [])
        return self._cached_functions

    def xrefs_to(self, address: int) -> list[dict[str, Any]]:
        data = self._run_script("export_xrefs.py", [f"0x{address:x}", "to"])
        return data.get("xrefs", [])

    def xrefs_from(self, address: int) -> list[dict[str, Any]]:
        data = self._run_script("export_xrefs.py", [f"0x{address:x}", "from"])
        return data.get("xrefs", [])

    def cfg(self, name_or_address: str | int) -> dict[str, Any]:
        target = str(name_or_address)
        if isinstance(name_or_address, int):
            target = f"0x{name_or_address:x}"
        return self._run_script("export_cfg.py", [target])

    def strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        data = self._run_script("export_strings.py", [str(min_length)])
        return data.get("strings", [])

    def close(self) -> None:
        self._cached_functions = None

    @property
    def binary_info(self) -> dict[str, Any]:
        return {
            "path": str(self._binary_path),
            "engine": "ghidra",
            "project_dir": str(self._get_project_dir()),
            "analyzed": self._analyzed,
        }
