"""VirtualBox VM connector via vboxmanage CLI."""
from __future__ import annotations
import json
import re
from pathlib import Path
from deepview.core.logging import get_logger
from deepview.core.types import VMInfo, SnapshotInfo
from deepview.core.exceptions import VMError, SnapshotError, ToolNotFoundError
from deepview.interfaces.vm_connector import VMConnector
from deepview.utils.process import find_tool, run_command

log = get_logger("vm.connectors.virtualbox")


class VirtualBoxConnector(VMConnector):
    @classmethod
    def connector_name(cls) -> str:
        return "vbox"

    def is_available(self) -> bool:
        try:
            find_tool("vboxmanage")
            return True
        except ToolNotFoundError:
            return False

    def connect(self, uri: str = "") -> None:
        pass  # VBoxManage is stateless

    def disconnect(self) -> None:
        pass

    def list_vms(self) -> list[VMInfo]:
        result = run_command(["vboxmanage", "list", "vms", "--long"])
        if not result.success:
            raise VMError(f"vboxmanage list failed: {result.stderr}")

        vms = []
        current: dict = {}
        for line in result.stdout.splitlines():
            if line.startswith("Name:"):
                if current:
                    vms.append(VMInfo(**current))
                current = {
                    "vm_id": "",
                    "name": line.split(":", 1)[1].strip(),
                    "state": "unknown",
                    "hypervisor": "vbox",
                }
            elif line.startswith("UUID:"):
                current["vm_id"] = line.split(":", 1)[1].strip()
            elif line.startswith("State:"):
                state_str = line.split(":", 1)[1].strip().lower()
                current["state"] = "running" if "running" in state_str else "stopped"
            elif line.startswith("Memory size:"):
                mem_str = line.split(":", 1)[1].strip()
                mem_match = re.search(r"(\d+)", mem_str)
                if mem_match:
                    current["memory_mb"] = int(mem_match.group(1))

        if current:
            vms.append(VMInfo(**current))
        return vms

    def snapshot(self, vm_id: str, name: str) -> SnapshotInfo:
        result = run_command(["vboxmanage", "snapshot", vm_id, "take", name])
        if not result.success:
            raise SnapshotError(f"Snapshot failed: {result.stderr}")
        return SnapshotInfo(snapshot_id=name, vm_id=vm_id, name=name, has_memory=True)

    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> None:
        result = run_command(["vboxmanage", "snapshot", vm_id, "delete", snapshot_id])
        if not result.success:
            raise SnapshotError(f"Delete failed: {result.stderr}")

    def extract_memory(self, vm_id: str, output: Path) -> Path:
        # VBox uses debugvm dumpvmcore for memory dumps
        result = run_command(["vboxmanage", "debugvm", vm_id, "dumpvmcore", f"--filename={output}"])
        if not result.success:
            raise VMError(f"Memory extraction failed: {result.stderr}")
        log.info("memory_extracted", vm=vm_id, output=str(output))
        return output
