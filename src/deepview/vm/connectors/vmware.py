"""VMware VM connector via vmrun CLI."""
from __future__ import annotations
from pathlib import Path
from deepview.core.logging import get_logger
from deepview.core.types import VMInfo, SnapshotInfo
from deepview.core.exceptions import VMError, SnapshotError, ToolNotFoundError
from deepview.interfaces.vm_connector import VMConnector
from deepview.utils.process import find_tool, run_command

log = get_logger("vm.connectors.vmware")


class VMwareConnector(VMConnector):
    @classmethod
    def connector_name(cls) -> str:
        return "vmware"

    def is_available(self) -> bool:
        try:
            find_tool("vmrun")
            return True
        except ToolNotFoundError:
            return False

    def connect(self, uri: str = "") -> None:
        pass  # vmrun is stateless

    def disconnect(self) -> None:
        pass

    def list_vms(self) -> list[VMInfo]:
        result = run_command(["vmrun", "list"])
        if not result.success:
            raise VMError(f"vmrun list failed: {result.stderr}")

        vms = []
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:  # Skip "Total running VMs: N"
            vmx_path = line.strip()
            if vmx_path:
                vms.append(VMInfo(
                    vm_id=vmx_path,
                    name=Path(vmx_path).stem,
                    state="running",
                    hypervisor="vmware",
                ))
        return vms

    def snapshot(self, vm_id: str, name: str) -> SnapshotInfo:
        result = run_command(["vmrun", "snapshot", vm_id, name])
        if not result.success:
            raise SnapshotError(f"Snapshot failed: {result.stderr}")
        return SnapshotInfo(snapshot_id=name, vm_id=vm_id, name=name, has_memory=True)

    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> None:
        result = run_command(["vmrun", "deleteSnapshot", vm_id, snapshot_id])
        if not result.success:
            raise SnapshotError(f"Delete failed: {result.stderr}")

    def extract_memory(self, vm_id: str, output: Path) -> Path:
        # VMware stores memory in .vmem files alongside the .vmx
        vmx = Path(vm_id)
        vmem = vmx.with_suffix(".vmem")
        if vmem.exists():
            import shutil
            shutil.copy2(vmem, output)
            log.info("memory_extracted", vm=vm_id, output=str(output))
            return output
        raise VMError(f"No .vmem file found for {vm_id}")
