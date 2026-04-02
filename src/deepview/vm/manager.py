"""VM subsystem orchestrator."""
from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger
from deepview.core.types import VMInfo, SnapshotInfo
from deepview.core.exceptions import VMError, VMConnectionError
from deepview.core.platform import detect_platform
from deepview.core.types import Platform
from deepview.interfaces.vm_connector import VMConnector

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("vm.manager")


class VMManager:
    """Orchestrates VM operations across hypervisors."""

    def __init__(self, context: AnalysisContext):
        self._context = context
        self._connectors: dict[str, VMConnector] = {}
        self._detect_connectors()

    def _detect_connectors(self) -> None:
        platform = detect_platform()

        connector_classes: list[type[VMConnector]] = []

        if platform == Platform.LINUX:
            try:
                from deepview.vm.connectors.qemu_kvm import QemuKVMConnector
                connector_classes.append(QemuKVMConnector)
            except Exception:
                pass

        try:
            from deepview.vm.connectors.virtualbox import VirtualBoxConnector
            connector_classes.append(VirtualBoxConnector)
        except Exception:
            pass

        try:
            from deepview.vm.connectors.vmware import VMwareConnector
            connector_classes.append(VMwareConnector)
        except Exception:
            pass

        for cls in connector_classes:
            try:
                conn = cls()
                if conn.is_available():
                    name = conn.connector_name()
                    self._connectors[name] = conn
                    log.info("connector_available", connector=name)
            except Exception:
                pass

    def get_connector(self, name: str = "auto") -> VMConnector:
        if name == "auto":
            if not self._connectors:
                raise VMError("No VM connector available")
            return next(iter(self._connectors.values()))
        if name not in self._connectors:
            raise VMError(f"Connector '{name}' not available. Available: {list(self._connectors.keys())}")
        return self._connectors[name]

    def list_vms(self, hypervisor: str = "auto") -> list[VMInfo]:
        connector = self.get_connector(hypervisor)
        return connector.list_vms()

    def snapshot(self, vm_id: str, name: str, hypervisor: str = "auto") -> SnapshotInfo:
        connector = self.get_connector(hypervisor)
        return connector.snapshot(vm_id, name)

    def extract_memory(self, vm_id: str, output: Path, hypervisor: str = "auto") -> Path:
        connector = self.get_connector(hypervisor)
        return connector.extract_memory(vm_id, output)

    @property
    def available_connectors(self) -> list[str]:
        return list(self._connectors.keys())
