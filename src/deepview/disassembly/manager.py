"""Disassembly and reverse-engineering subsystem orchestrator."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from deepview.core.exceptions import EngineNotAvailableError
from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.interfaces.disassembler import DisassemblyEngine, DisassemblySession

log = get_logger("disassembly.manager")

# Engine preference order (most capable first).
_PREFERENCE = ("ghidra", "hopper", "capstone")


class DisassemblyManager:
    """Orchestrates disassembly and reverse-engineering backends.

    Auto-detects available engines at init following the same pattern as
    :class:`~deepview.memory.manager.MemoryManager`.
    """

    def __init__(self, context: AnalysisContext) -> None:
        self._context = context
        self._engines: dict[str, DisassemblyEngine] = {}
        self._sessions: dict[str, DisassemblySession] = {}
        self._detect_engines()

    # ------------------------------------------------------------------
    # Engine discovery
    # ------------------------------------------------------------------

    def _detect_engines(self) -> None:
        """Probe for available disassembly backends."""
        # Ghidra
        try:
            from deepview.disassembly.engines.ghidra import GhidraEngine

            engine = GhidraEngine(self._context.config.disassembly)
            if engine.is_available():
                self._engines["ghidra"] = engine
                log.info("engine_available", engine="ghidra")
        except Exception as exc:
            log.debug("engine_probe_failed", engine="ghidra", reason=str(exc))

        # Hopper
        try:
            from deepview.disassembly.engines.hopper import HopperEngine

            engine = HopperEngine(self._context.config.disassembly)
            if engine.is_available():
                self._engines["hopper"] = engine
                log.info("engine_available", engine="hopper")
        except Exception as exc:
            log.debug("engine_probe_failed", engine="hopper", reason=str(exc))

        # Capstone (lightweight fallback)
        try:
            from deepview.disassembly.engines.capstone_engine import CapstoneEngine

            engine = CapstoneEngine()
            if engine.is_available():
                self._engines["capstone"] = engine
                log.info("engine_available", engine="capstone")
        except Exception as exc:
            log.debug("engine_probe_failed", engine="capstone", reason=str(exc))

    # ------------------------------------------------------------------
    # Engine selection
    # ------------------------------------------------------------------

    def get_engine(self, name: str = "auto") -> DisassemblyEngine:
        """Return an engine by name, or the best available for ``"auto"``."""
        if name == "auto":
            for preferred in _PREFERENCE:
                if preferred in self._engines:
                    return self._engines[preferred]
            raise EngineNotAvailableError(
                "No disassembly engine available. "
                "Install Ghidra, Hopper, or capstone "
                "(pip install 'deepview[disassembly]')."
            )
        if name not in self._engines:
            raise EngineNotAvailableError(
                f"Engine '{name}' not available. "
                f"Available: {list(self._engines)}"
            )
        return self._engines[name]

    @property
    def available_engines(self) -> list[str]:
        """Names of all detected disassembly engines."""
        return list(self._engines)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def open(self, path: Path, engine: str = "auto") -> DisassemblySession:
        """Open a binary for analysis, caching sessions by (engine, path)."""
        key = f"{engine}:{path}"
        if key not in self._sessions:
            eng = self.get_engine(engine)
            self._sessions[key] = eng.open_binary(path)
            log.info("session_opened", engine=eng.engine_name(), path=str(path))
        return self._sessions[key]

    def close_all(self) -> None:
        """Release all cached sessions."""
        for session in self._sessions.values():
            try:
                session.close()
            except Exception:
                pass
        self._sessions.clear()

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def disassemble(
        self,
        path: Path,
        address: int,
        count: int = 20,
        engine: str = "auto",
    ) -> list[dict[str, Any]]:
        """Disassemble *count* instructions at *address*."""
        return self.open(path, engine).disassemble(address, count)

    def decompile(
        self,
        path: Path,
        target: str | int,
        engine: str = "auto",
    ) -> str:
        """Decompile a function to pseudo-C."""
        return self.open(path, engine).decompile(target)

    def functions(
        self,
        path: Path,
        engine: str = "auto",
    ) -> list[dict[str, Any]]:
        """List identified functions in *path*."""
        return self.open(path, engine).functions()

    def xrefs(
        self,
        path: Path,
        address: int,
        direction: str = "to",
        engine: str = "auto",
    ) -> list[dict[str, Any]]:
        """Return cross-references to or from *address*."""
        session = self.open(path, engine)
        if direction == "from":
            return session.xrefs_from(address)
        return session.xrefs_to(address)

    def cfg(
        self,
        path: Path,
        target: str | int,
        engine: str = "auto",
    ) -> dict[str, Any]:
        """Return the control-flow graph for a function."""
        return self.open(path, engine).cfg(target)
