from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from deepview.core.types import SnapshotInfo, VMInfo


class VMConnector(ABC):
    """Abstract interface for hypervisor / VM management operations."""

    @abstractmethod
    def connect(self, uri: str = "") -> None:
        """Open a connection to the hypervisor at *uri*."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the hypervisor connection."""

    @abstractmethod
    def list_vms(self) -> list[VMInfo]:
        """Enumerate all virtual machines visible to this connector."""

    @abstractmethod
    def snapshot(self, vm_id: str, name: str) -> SnapshotInfo:
        """Create a snapshot of *vm_id* named *name*."""

    @abstractmethod
    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> None:
        """Delete the snapshot identified by *snapshot_id* from *vm_id*."""

    @abstractmethod
    def extract_memory(self, vm_id: str, output: Path) -> Path:
        """Dump the memory of *vm_id* to *output* and return the path."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` when the hypervisor backend is reachable."""

    @classmethod
    @abstractmethod
    def connector_name(cls) -> str:
        """Human-readable name for this VM connector."""
