"""Snapshot management utilities."""
from __future__ import annotations
from pathlib import Path
from deepview.core.types import SnapshotInfo
from deepview.core.logging import get_logger

log = get_logger("vm.snapshot")


class SnapshotManager:
    """Manages VM snapshots and their lifecycle."""

    def __init__(self, vm_manager):
        self._vm_manager = vm_manager

    def create_and_extract(self, vm_id: str, snapshot_name: str, output: Path,
                           hypervisor: str = "auto") -> tuple[SnapshotInfo, Path]:
        """Create a snapshot and extract its memory in one step."""
        connector = self._vm_manager.get_connector(hypervisor)

        log.info("snapshot_and_extract", vm=vm_id, snapshot=snapshot_name)
        snap = connector.snapshot(vm_id, snapshot_name)
        mem_path = connector.extract_memory(vm_id, output)

        return snap, mem_path
