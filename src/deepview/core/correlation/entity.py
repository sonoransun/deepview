"""Typed forensic entities that live as nodes in the correlation graph.

Entities have a **stable** ``entity_id`` so the same real-world object
(process, file, flow, ...) reported from different subsystems merges into a
single node. Attributes accumulate via
:meth:`ForensicEntity.merge_attributes`, so live-trace observations refine
post-hoc memory analysis findings (or vice versa).
"""
from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field

from deepview.core.types import ProcessContext


class EntityKind(str, enum.Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK_FLOW = "network_flow"
    MODULE = "module"
    MEMORY_REGION = "memory_region"
    CREDENTIAL = "credential"
    HOST = "host"
    PERSISTENCE = "persistence"
    FINDING = "finding"


class ForensicEntity(BaseModel):
    """Base class for all correlation-graph nodes."""

    entity_id: str
    kind: EntityKind
    first_seen_ns: int = 0
    last_seen_ns: int = 0
    labels: set[str] = Field(default_factory=set)
    attributes: dict[str, Any] = Field(default_factory=dict)

    def merge_attributes(self, other: dict[str, Any]) -> None:
        """Merge a new attribute dict into this entity's attribute store.

        Newer values overwrite older ones only when the new value is non-empty
        (empty string, 0, None, empty container are treated as "no info"). This
        preserves rich data when a later subsystem reports a skeletal view.
        """
        for key, value in other.items():
            if value in (None, "", 0, [], {}, set()):
                continue
            self.attributes[key] = value

    def observe(self, timestamp_ns: int) -> None:
        """Update first/last-seen timestamps."""
        if timestamp_ns <= 0:
            return
        if self.first_seen_ns == 0 or timestamp_ns < self.first_seen_ns:
            self.first_seen_ns = timestamp_ns
        if timestamp_ns > self.last_seen_ns:
            self.last_seen_ns = timestamp_ns


class ProcessEntity(ForensicEntity):
    """A running (or once-running) process/thread."""

    kind: EntityKind = EntityKind.PROCESS
    pid: int
    ppid: int = 0
    comm: str = ""
    exe_path: str = ""
    container_id: str = ""

    @classmethod
    def from_context(cls, ctx: ProcessContext, boot_ns: int | None = None) -> ProcessEntity:
        return cls(
            entity_id=ctx.stable_key(boot_ns),
            pid=ctx.pid,
            ppid=ctx.ppid,
            comm=ctx.comm,
            exe_path=ctx.exe_path,
            container_id=ctx.container_id,
            attributes={
                "cmdline": list(ctx.cmdline),
                "cwd": ctx.cwd,
                "uid": ctx.uid,
                "gid": ctx.gid,
                "exe_hash_sha256": ctx.exe_hash_sha256,
                "integrity_level": ctx.integrity_level,
                "selinux_context": ctx.selinux_context,
                "k8s_pod": ctx.k8s_pod,
                "k8s_namespace": ctx.k8s_namespace,
            },
        )


class FileEntity(ForensicEntity):
    """A file on disk, keyed by ``file:<inode>@<device>`` when possible."""

    kind: EntityKind = EntityKind.FILE
    path: str = ""
    inode: int = 0
    device: str = ""
    sha256: str = ""

    @classmethod
    def from_path(
        cls,
        path: str,
        inode: int = 0,
        device: str = "",
        sha256: str = "",
    ) -> FileEntity:
        if inode and device:
            eid = f"file:{inode}@{device}"
        elif sha256:
            eid = f"file:sha256={sha256}"
        else:
            eid = f"file:{path}"
        return cls(
            entity_id=eid,
            path=path,
            inode=inode,
            device=device,
            sha256=sha256,
        )


class NetworkFlowEntity(ForensicEntity):
    """A 5-tuple network flow (connection)."""

    kind: EntityKind = EntityKind.NETWORK_FLOW
    protocol: str = "tcp"
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0

    @classmethod
    def from_tuple(
        cls,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        start_ns: int = 0,
    ) -> NetworkFlowEntity:
        eid = (
            f"flow:{protocol}:{src_ip}:{src_port}->{dst_ip}:{dst_port}@{start_ns}"
        )
        return cls(
            entity_id=eid,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            first_seen_ns=start_ns,
            last_seen_ns=start_ns,
        )


class ModuleEntity(ForensicEntity):
    """A loaded module (shared library, DLL, kernel module, kext, BPF prog)."""

    kind: EntityKind = EntityKind.MODULE
    name: str = ""
    path: str = ""
    base_address: int = 0

    @classmethod
    def from_module(cls, name: str, path: str = "", base: int = 0) -> ModuleEntity:
        eid = f"module:{name}@{hex(base)}" if base else f"module:{name}"
        return cls(entity_id=eid, name=name, path=path, base_address=base)


class MemoryRegionEntity(ForensicEntity):
    """A process memory region (VAD / VMA)."""

    kind: EntityKind = EntityKind.MEMORY_REGION
    owning_pid: int = 0
    start: int = 0
    end: int = 0
    protection: str = ""

    @classmethod
    def from_region(
        cls, pid: int, start: int, end: int, protection: str = ""
    ) -> MemoryRegionEntity:
        return cls(
            entity_id=f"mem:{pid}:{hex(start)}-{hex(end)}",
            owning_pid=pid,
            start=start,
            end=end,
            protection=protection,
        )


class CredentialEntity(ForensicEntity):
    """A discovered credential artifact (key, token, hash)."""

    kind: EntityKind = EntityKind.CREDENTIAL
    credential_type: str = ""  # aes, rsa, tls_master, ssh_host, kerberos, ...
    source: str = ""  # memory image, file path
    offset: int = 0

    @classmethod
    def make(
        cls,
        credential_type: str,
        source: str,
        offset: int = 0,
        fingerprint: str = "",
    ) -> CredentialEntity:
        key = fingerprint or f"{source}:{offset}"
        return cls(
            entity_id=f"cred:{credential_type}:{key}",
            credential_type=credential_type,
            source=source,
            offset=offset,
        )


class HostEntity(ForensicEntity):
    """A host / machine under analysis."""

    kind: EntityKind = EntityKind.HOST
    hostname: str = ""
    os: str = ""

    @classmethod
    def make(cls, hostname: str, os: str = "") -> HostEntity:
        return cls(entity_id=f"host:{hostname}", hostname=hostname, os=os)


class PersistenceEntity(ForensicEntity):
    """A persistence artifact (cron, systemd unit, registry key, launchd plist)."""

    kind: EntityKind = EntityKind.PERSISTENCE
    mechanism: str = ""  # "cron", "systemd", "launchd", "registry_run", ...
    location: str = ""
    mitre_technique: str = ""

    @classmethod
    def make(
        cls,
        mechanism: str,
        location: str,
        mitre_technique: str = "",
    ) -> PersistenceEntity:
        return cls(
            entity_id=f"persist:{mechanism}:{location}",
            mechanism=mechanism,
            location=location,
            mitre_technique=mitre_technique,
        )
