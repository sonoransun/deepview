"""QEMU/KVM VM connector via libvirt."""
from __future__ import annotations
from pathlib import Path
from deepview.core.logging import get_logger
from deepview.core.types import VMInfo, SnapshotInfo, Platform
from deepview.core.exceptions import VMError, VMConnectionError, SnapshotError
from deepview.interfaces.vm_connector import VMConnector

log = get_logger("vm.connectors.qemu_kvm")


class QemuKVMConnector(VMConnector):
    """VM connector for QEMU/KVM via libvirt-python."""

    def __init__(self):
        self._conn = None
        self._available = False
        try:
            import libvirt
            self._libvirt = libvirt
            self._available = True
        except ImportError:
            log.debug("libvirt_not_installed")

    @classmethod
    def connector_name(cls) -> str:
        return "qemu"

    def is_available(self) -> bool:
        return self._available

    def connect(self, uri: str = "qemu:///system") -> None:
        if not self._available:
            raise VMConnectionError("libvirt-python not installed")
        try:
            self._conn = self._libvirt.open(uri)
            if self._conn is None:
                raise VMConnectionError(f"Failed to connect to {uri}")
            log.info("connected", uri=uri)
        except self._libvirt.libvirtError as e:
            raise VMConnectionError(f"libvirt connection failed: {e}") from e

    def disconnect(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_connected(self) -> None:
        if self._conn is None:
            self.connect()

    def list_vms(self) -> list[VMInfo]:
        self._ensure_connected()
        vms = []
        # Running VMs
        for dom_id in self._conn.listDomainsID():
            dom = self._conn.lookupByID(dom_id)
            info = dom.info()
            vms.append(VMInfo(
                vm_id=dom.UUIDString(),
                name=dom.name(),
                state="running",
                hypervisor="qemu",
                memory_mb=info[2] // 1024,
            ))
        # Stopped VMs
        for name in self._conn.listDefinedDomains():
            dom = self._conn.lookupByName(name)
            info = dom.info()
            vms.append(VMInfo(
                vm_id=dom.UUIDString(),
                name=name,
                state="stopped",
                hypervisor="qemu",
                memory_mb=info[1] // 1024,
            ))
        return vms

    def snapshot(self, vm_id: str, name: str) -> SnapshotInfo:
        self._ensure_connected()
        try:
            dom = self._conn.lookupByUUIDString(vm_id)
        except Exception:
            dom = self._conn.lookupByName(vm_id)

        snap_xml = f"<domainsnapshot><name>{name}</name><memory snapshot='internal'/></domainsnapshot>"
        try:
            snap = dom.snapshotCreateXML(snap_xml, 0)
            return SnapshotInfo(
                snapshot_id=name,
                vm_id=vm_id,
                name=name,
                has_memory=True,
            )
        except self._libvirt.libvirtError as e:
            raise SnapshotError(f"Snapshot failed: {e}") from e

    def delete_snapshot(self, vm_id: str, snapshot_id: str) -> None:
        self._ensure_connected()
        try:
            dom = self._conn.lookupByUUIDString(vm_id)
        except Exception:
            dom = self._conn.lookupByName(vm_id)
        snap = dom.snapshotLookupByName(snapshot_id, 0)
        snap.delete(0)

    def extract_memory(self, vm_id: str, output: Path) -> Path:
        self._ensure_connected()
        try:
            dom = self._conn.lookupByUUIDString(vm_id)
        except Exception:
            dom = self._conn.lookupByName(vm_id)

        # Use virsh dump for memory extraction
        from deepview.utils.process import run_command
        result = run_command(["virsh", "dump", dom.name(), str(output), "--memory-only"], timeout=600)
        if not result.success:
            raise VMError(f"Memory extraction failed: {result.stderr}")

        log.info("memory_extracted", vm=dom.name(), output=str(output))
        return output
