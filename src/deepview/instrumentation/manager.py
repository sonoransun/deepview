"""Instrumentation subsystem orchestrator."""
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger
from deepview.core.exceptions import InstrumentationError
from deepview.interfaces.instrumentor import HookDefinition
from deepview.tracing.stream import TraceEventBus
from deepview.instrumentation.bridge import FridaBridge

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("instrumentation.manager")


class InstrumentationManager:
    """Orchestrates application instrumentation."""

    def __init__(self, context: AnalysisContext, event_bus: TraceEventBus | None = None):
        self._context = context
        self._bus = event_bus or TraceEventBus()
        self._bridge = FridaBridge(self._bus)
        self._sessions: dict[int, object] = {}
        self._frida = None

    def _get_frida(self):
        if self._frida is None:
            from deepview.instrumentation.frida_engine import FridaEngine
            self._frida = FridaEngine()
        return self._frida

    def attach(self, target: int | str) -> int:
        """Attach to a process. Returns PID."""
        engine = self._get_frida()
        session = engine.attach(target)
        session.on_message(self._bridge.handle_message)
        pid = session.pid
        self._sessions[pid] = session
        return pid

    def add_hook(self, pid: int, hook: HookDefinition) -> None:
        session = self._sessions.get(pid)
        if not session:
            raise InstrumentationError(f"No session for PID {pid}")
        session.inject_hook(hook)

    def detach(self, pid: int) -> None:
        session = self._sessions.pop(pid, None)
        if session:
            engine = self._get_frida()
            engine.detach(session)

    def detach_all(self) -> None:
        for pid in list(self._sessions.keys()):
            self.detach(pid)

    def analyze_binary(self, path: Path) -> dict:
        """Analyze a binary and return its structure."""
        from deepview.instrumentation.binary.analyzer import BinaryAnalyzer
        analyzer = BinaryAnalyzer(path)
        return analyzer.summary()

    def find_instrumentation_points(self, path: Path, strategy: str = "all") -> list[dict]:
        """Find instrumentation points in a binary."""
        from deepview.instrumentation.binary.analyzer import BinaryAnalyzer
        from deepview.instrumentation.binary.points import InstrumentationPointFinder

        analyzer = BinaryAnalyzer(path)
        finder = InstrumentationPointFinder(analyzer)

        if strategy == "exports":
            points = finder.find_exports()
        elif strategy == "security":
            points = finder.find_security_sensitive()
        else:
            points = finder.find_all()

        return [
            {"name": pt.name, "address": hex(pt.address), "type": pt.point_type, "module": pt.module}
            for pt in points
        ]

    def reassemble(self, input_path: Path, output_path: Path,
                    strategy: str = "security") -> Path:
        """Build a reassembled binary with embedded monitoring."""
        from deepview.instrumentation.binary.reassembler import BinaryReassembler

        builder = BinaryReassembler(input_path, output_path)
        if strategy == "security":
            count = builder.add_hooks_for_security_sensitive()
        else:
            count = builder.add_hooks_for_exports()

        log.info("reassembling", hooks=count, strategy=strategy)
        return builder.build()

    def decompile_function(self, path: Path, function: str,
                           engine: str = "auto") -> str:
        """Decompile a function via the disassembly subsystem."""
        from deepview.disassembly.manager import DisassemblyManager

        dm = DisassemblyManager(self._context)
        try:
            return dm.decompile(path, function, engine)
        finally:
            dm.close_all()

    @property
    def event_bus(self) -> TraceEventBus:
        return self._bus
