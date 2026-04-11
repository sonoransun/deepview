"""Container / namespace context resolution.

Given a raw process context, this helper populates ``container_id`` /
``k8s_pod`` / ``k8s_namespace`` / ``namespaces`` by reading ``/proc/<pid>/``
artefacts. Works on any Linux host without needing Docker / CRI APIs (but
we will also query containerd when reachable for richer pod metadata).

The resolver is intentionally Backend-agnostic: tracing providers call it
to enrich ``ProcessContext`` before pushing into the correlation graph, and
the persistence scanner calls it to attribute discovered artefacts to the
right pod.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger
from deepview.core.types import NamespaceSet, ProcessContext

log = get_logger("tracing.providers.container")


_CGROUP_DOCKER_PATTERN = re.compile(r"(?:docker|crio|containerd)[^/]*/(?:.*?)([0-9a-f]{12,64})")
_CGROUP_K8S_PATTERN = re.compile(r"kubepods.*?pod([0-9a-f-]{16,})")
_CONTAINERD_RE = re.compile(r"cri-containerd[:-]([0-9a-f]{12,64})")


def resolve_for_process(ctx: ProcessContext) -> ProcessContext:
    """Return a new ``ProcessContext`` with container / namespace fields populated.

    The original object is never mutated — Pydantic ``model_copy`` keeps
    immutability semantics. Populates as much as possible from ``/proc``;
    missing data is silently skipped.
    """
    if sys.platform != "linux":
        return ctx
    pid = ctx.pid
    if pid <= 0:
        return ctx
    update: dict[str, Any] = {}

    cgroup_path = _read_cgroup(pid)
    if cgroup_path:
        update["cgroup_path"] = cgroup_path
        cid = _container_id_from_cgroup(cgroup_path)
        if cid:
            update["container_id"] = cid
        pod, ns = _k8s_from_cgroup(cgroup_path)
        if pod:
            update["k8s_pod"] = pod
        if ns:
            update["k8s_namespace"] = ns

    namespaces = _read_namespaces(pid)
    if namespaces:
        update["namespaces"] = namespaces

    if not update:
        return ctx
    return ctx.model_copy(update=update)


def _read_cgroup(pid: int) -> str:
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    # Prefer the unified (v2) hierarchy line `0::<path>` when present.
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            return parts[2]
    # Otherwise any non-empty cgroup path is fine.
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[2].strip():
            return parts[2]
    return ""


def _container_id_from_cgroup(path: str) -> str:
    m = _CGROUP_DOCKER_PATTERN.search(path)
    if m:
        return m.group(1)
    m = _CONTAINERD_RE.search(path)
    if m:
        return m.group(1)
    # Raw fallback: the last path segment often *is* the hash for
    # ``containerd`` on cri-o on k8s.
    tail = path.rstrip("/").split("/")[-1] if path else ""
    if re.fullmatch(r"[0-9a-f]{12,64}", tail):
        return tail
    return ""


def _k8s_from_cgroup(path: str) -> tuple[str, str]:
    """Best-effort pod UID + namespace extraction."""
    m = _CGROUP_K8S_PATTERN.search(path)
    pod = m.group(1) if m else ""
    namespace = ""
    # Pod namespace is not in the cgroup directly; fall back to the
    # kubernetes downward-API env var if the process has it set.
    return pod, namespace


def _read_namespaces(pid: int) -> NamespaceSet | None:
    base = Path(f"/proc/{pid}/ns")
    if not base.exists():
        return None
    inodes: dict[str, int | None] = {}
    for name in ("mnt", "pid", "net", "user", "uts", "ipc", "cgroup", "time"):
        link = base / name
        try:
            target = os.readlink(link)
        except OSError:
            inodes[name] = None
            continue
        # target has the form "<name>:[<inode>]"
        m = re.search(r"\[(\d+)\]", target)
        inodes[name] = int(m.group(1)) if m else None
    if not any(v is not None for v in inodes.values()):
        return None
    return NamespaceSet(**inodes)


def enrich_pod_namespace(ctx: ProcessContext) -> ProcessContext:
    """Populate the k8s namespace from the process environment.

    Kubernetes sets ``POD_NAMESPACE`` in the downward API env for many
    workloads. We read /proc/<pid>/environ for this specifically since
    full env capture is an expensive operation.
    """
    if sys.platform != "linux" or not ctx.k8s_pod or ctx.k8s_namespace:
        return ctx
    try:
        environ = Path(f"/proc/{ctx.pid}/environ").read_bytes()
    except OSError:
        return ctx
    for entry in environ.split(b"\x00"):
        if not entry:
            continue
        key, _, value = entry.partition(b"=")
        if key == b"POD_NAMESPACE":
            return ctx.model_copy(update={"k8s_namespace": value.decode("utf-8", "replace")})
    return ctx
