"""Memory subsystem orchestrator."""
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger
from deepview.core.types import DumpFormat, AcquisitionTarget, AcquisitionResult
from deepview.core.exceptions import FormatError, AnalysisError
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.interfaces.acquisition import MemoryAcquisitionProvider
    from deepview.interfaces.analysis import AnalysisEngine

log = get_logger("memory.manager")


class MemoryManager:
    """Orchestrates memory acquisition, format detection, and analysis."""

    def __init__(self, context: AnalysisContext):
        self._context = context
        self._engines: dict[str, AnalysisEngine] = {}
        self._providers: dict[str, MemoryAcquisitionProvider] = {}
        self._detect_engines()
        self._detect_providers()

    def _detect_engines(self) -> None:
        """Detect available analysis engines."""
        try:
            from deepview.memory.analysis.volatility import VolatilityEngine
            engine = VolatilityEngine()
            if engine.is_available():
                self._engines["volatility"] = engine
                log.info("engine_available", engine="volatility")
        except Exception:
            log.debug("engine_unavailable", engine="volatility")

        try:
            from deepview.memory.analysis.memprocfs import MemProcFSEngine
            engine = MemProcFSEngine()
            if engine.is_available():
                self._engines["memprocfs"] = engine
                log.info("engine_available", engine="memprocfs")
        except Exception:
            log.debug("engine_unavailable", engine="memprocfs")

    def _detect_providers(self) -> None:
        """Detect available acquisition providers."""
        from deepview.core.platform import detect_platform
        from deepview.core.types import Platform

        platform = detect_platform()

        provider_classes = []
        if platform == Platform.LINUX:
            try:
                from deepview.memory.acquisition.avml import AVMLProvider
                provider_classes.append(AVMLProvider)
            except Exception:
                pass
            try:
                from deepview.memory.acquisition.lime import LiMEProvider
                provider_classes.append(LiMEProvider)
            except Exception:
                pass
        elif platform == Platform.MACOS:
            try:
                from deepview.memory.acquisition.osxpmem import OSXPmemProvider
                provider_classes.append(OSXPmemProvider)
            except Exception:
                pass
        elif platform == Platform.WINDOWS:
            try:
                from deepview.memory.acquisition.winpmem import WinPmemProvider
                provider_classes.append(WinPmemProvider)
            except Exception:
                pass

        try:
            from deepview.memory.acquisition.live import LiveMemoryProvider
            provider_classes.append(LiveMemoryProvider)
        except Exception:
            pass

        for cls in provider_classes:
            try:
                provider = cls()
                if provider.is_available():
                    self._providers[provider.provider_name()] = provider
                    log.info("provider_available", provider=provider.provider_name())
            except Exception:
                pass

    def detect_format(self, path: Path) -> DumpFormat:
        """Auto-detect the format of a memory dump file."""
        with open(path, "rb") as f:
            magic = f.read(8)

        # LiME magic
        if len(magic) >= 4:
            import struct
            lime_magic = struct.unpack("<I", magic[:4])[0]
            if lime_magic == 0x4C694D45:
                return DumpFormat.LIME

        # ELF magic
        if magic[:4] == b"\x7fELF":
            return DumpFormat.ELF_CORE

        # Windows crash dump
        if magic[:4] == b"PAGE" or magic[:8] == b"PAGEDU64":
            return DumpFormat.CRASHDUMP

        return DumpFormat.RAW

    def open_layer(self, path: Path, fmt: DumpFormat | None = None, name: str = "") -> DataLayer:
        """Open a memory dump as a DataLayer."""
        if fmt is None:
            fmt = self.detect_format(path)

        log.info("opening_layer", path=str(path), format=fmt.value)

        if fmt == DumpFormat.RAW:
            from deepview.memory.formats.raw import RawMemoryLayer
            return RawMemoryLayer(path, name)
        elif fmt == DumpFormat.LIME:
            from deepview.memory.formats.lime_format import LiMEMemoryLayer
            return LiMEMemoryLayer(path, name)
        elif fmt == DumpFormat.ELF_CORE:
            from deepview.memory.formats.elf_core import ELFCoreLayer
            return ELFCoreLayer(path, name)
        elif fmt == DumpFormat.CRASHDUMP:
            from deepview.memory.formats.crashdump import CrashDumpLayer
            return CrashDumpLayer(path, name)
        else:
            raise FormatError(f"Unsupported format: {fmt}")

    def get_engine(self, name: str = "auto") -> AnalysisEngine:
        """Get an analysis engine by name."""
        if name == "auto":
            # Prefer volatility, fall back to memprocfs
            for preferred in ["volatility", "memprocfs"]:
                if preferred in self._engines:
                    return self._engines[preferred]
            raise AnalysisError("No analysis engine available. Install volatility3 or memprocfs.")

        if name not in self._engines:
            raise AnalysisError(f"Engine '{name}' not available. Available: {list(self._engines.keys())}")
        return self._engines[name]

    def acquire(self, target: AcquisitionTarget | None = None, output: Path = Path("memory.raw"),
                method: str = "auto", fmt: DumpFormat = DumpFormat.RAW) -> AcquisitionResult:
        """Acquire memory from the live system or a target."""
        target = target or AcquisitionTarget()

        if method == "auto":
            for provider in self._providers.values():
                try:
                    return provider.acquire(target, output, fmt)
                except Exception as e:
                    log.warning("acquisition_failed", provider=provider.provider_name(), error=str(e))
            raise AnalysisError("No acquisition method succeeded.")

        if method not in self._providers:
            raise AnalysisError(f"Provider '{method}' not available. Available: {list(self._providers.keys())}")
        return self._providers[method].acquire(target, output, fmt)

    @property
    def available_engines(self) -> list[str]:
        return list(self._engines.keys())

    @property
    def available_providers(self) -> list[str]:
        return list(self._providers.keys())
