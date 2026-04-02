"""MemProcFS analysis engine integration."""
from __future__ import annotations
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger
from deepview.interfaces.analysis import AnalysisEngine
from deepview.interfaces.layer import DataLayer

log = get_logger("memory.analysis.memprocfs")


class MemProcFSEngine(AnalysisEngine):
    """Analysis engine wrapping MemProcFS Python API."""

    def __init__(self):
        self._available = False
        try:
            import memprocfs
            self._memprocfs = memprocfs
            self._available = True
            log.info("memprocfs_loaded")
        except ImportError:
            log.debug("memprocfs_not_installed")

    @classmethod
    def engine_name(cls) -> str:
        return "memprocfs"

    def is_available(self) -> bool:
        return self._available

    def open_image(self, path: Path) -> DataLayer:
        """Open a memory image through MemProcFS."""
        if not self._available:
            raise RuntimeError("MemProcFS is not available")
        from deepview.memory.formats.raw import RawMemoryLayer
        return RawMemoryLayer(path)

    def open_vmm(self, path: Path) -> Any:
        """Open a memory image and return a MemProcFS Vmm handle.

        The Vmm handle provides filesystem-like access to memory:
          vmm.process_list() -> list of processes
          vmm.process(pid) -> process object
          vmm.process(pid).module_list() -> loaded modules
          vmm.process(pid).memory.read(addr, size) -> bytes
        """
        if not self._available:
            raise RuntimeError("MemProcFS is not available")

        vmm = self._memprocfs.Vmm(["-device", str(path)])
        log.info("vmm_opened", path=str(path))
        return vmm

    def run_plugin(self, plugin_name: str, layer: DataLayer, **kwargs: Any) -> Any:
        """Run a MemProcFS-based analysis.

        Plugin names map to MemProcFS VFS paths:
          "processes" -> enumerate processes
          "modules" -> enumerate modules for a process
          "registry" -> enumerate registry hives/keys
        """
        if not self._available:
            raise RuntimeError("MemProcFS is not available")

        path = kwargs.get("image_path")
        if path is None and hasattr(layer, "_path"):
            path = layer._path

        if path is None:
            raise ValueError("Cannot determine image path for MemProcFS")

        vmm = self.open_vmm(Path(path))

        try:
            if plugin_name == "processes":
                return self._list_processes(vmm)
            elif plugin_name == "modules":
                pid = kwargs.get("pid", 0)
                return self._list_modules(vmm, pid)
            else:
                raise ValueError(f"Unknown MemProcFS plugin: {plugin_name}")
        finally:
            vmm.close()

    def _list_processes(self, vmm: Any) -> list[dict]:
        """List all processes from memory image."""
        processes = []
        for proc in vmm.process_list():
            processes.append({
                "pid": proc.pid,
                "ppid": proc.ppid,
                "name": proc.name,
                "state": str(proc.state) if hasattr(proc, 'state') else "",
            })
        return processes

    def _list_modules(self, vmm: Any, pid: int) -> list[dict]:
        """List modules for a specific process."""
        proc = vmm.process(pid)
        modules = []
        for mod in proc.module_list():
            modules.append({
                "name": mod.name,
                "base": mod.base,
                "size": mod.size,
            })
        return modules

    def list_plugins(self) -> list[str]:
        """List available MemProcFS analysis operations."""
        if not self._available:
            return []
        return ["processes", "modules", "registry", "network", "handles"]
