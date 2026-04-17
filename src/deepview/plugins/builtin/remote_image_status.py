"""Report configured remote acquisition endpoints and transport availability.

This plugin is a read-only status surface: it inventories any remote
endpoints declared in the active :class:`DeepViewConfig` (see
``config.remote_endpoints``) and asks each transport-specific provider
module whether its optional dependencies are importable. It never
establishes a network connection, never prints a secret, and never reads
the bytes behind ``password_env`` / ``identity_file`` / ``tls_ca`` — it
only reports *whether* a credential can be resolved.

If the remote acquisition subsystem is not shipped in the current install
(slice 19 not yet merged, or the package was partially installed), the
plugin degrades to an empty result with a clear metadata marker rather
than raising.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin

# Map each supported transport selector (matching
# :func:`deepview.memory.acquisition.remote.factory.build_remote_provider`)
# to the dotted module path that owns its concrete provider. The plugin
# imports the module lazily to probe availability without dragging in
# optional transport deps at plugin-registration time.
_TRANSPORT_MODULES: dict[str, str] = {
    "ssh": "deepview.memory.acquisition.remote.ssh_dd",
    "tcp": "deepview.memory.acquisition.remote.tcp_stream",
    "udp": "deepview.memory.acquisition.remote.tcp_stream",
    "agent": "deepview.memory.acquisition.remote.network_agent",
    "lime": "deepview.memory.acquisition.remote.lime_remote",
    "dma-tb": "deepview.memory.acquisition.remote.dma_thunderbolt",
    "dma-pcie": "deepview.memory.acquisition.remote.dma_pcie",
    "dma-fw": "deepview.memory.acquisition.remote.dma_firewire",
    "ipmi": "deepview.memory.acquisition.remote.ipmi",
    "amt": "deepview.memory.acquisition.remote.intel_amt",
}


@register_plugin(
    name="remote_image_status",
    category=PluginCategory.NETWORK_FORENSICS,
    description="List configured remote acquisition endpoints and probe transport availability.",
    tags=["remote", "acquisition", "status"],
)
class RemoteImageStatusPlugin(DeepViewPlugin):
    """Inventory ``config.remote_endpoints`` without revealing credentials."""

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="show_credentials",
                description="Show resolved credentials (DANGEROUS, default false)",
                required=False,
                default=False,
            ),
        ]

    def run(self) -> PluginResult:
        columns = [
            "Host",
            "Transport",
            "Port",
            "Provider",
            "Available",
            "TLSRequired",
            "CredentialsResolved",
        ]

        # 1. Lazy-import the remote factory. If the subsystem is not
        # shipped yet (slice 19 not merged), return an empty result with
        # a clear "not available" marker.
        try:
            importlib.import_module("deepview.memory.acquisition.remote.factory")
        except Exception as exc:  # noqa: BLE001
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={
                    "error": "Remote acquisition subsystem not available",
                    "reason": str(exc),
                    "total": 0,
                    "available": 0,
                    "unavailable": 0,
                },
            )

        # 2. Pull configured endpoints. Slice 19 may or may not have
        # wired this into :class:`DeepViewConfig` yet; treat any missing
        # attribute or None as "no endpoints declared".
        raw_endpoints = getattr(self.context.config, "remote_endpoints", None) or []

        rows: list[dict[str, Any]] = []
        available_count = 0
        unavailable_count = 0

        for ep in raw_endpoints:
            host = _get(ep, "host", "")
            transport = str(_get(ep, "transport", "") or "").lower()
            port = _get(ep, "port", None)
            require_tls = bool(_get(ep, "require_tls", False))
            password_env = _get(ep, "password_env", None)
            identity_file = _get(ep, "identity_file", None)
            tls_ca = _get(ep, "tls_ca", None)

            module_path = _TRANSPORT_MODULES.get(transport)
            provider_name = ""
            available = False
            if module_path is None:
                provider_name = "<unknown>"
                available = False
            else:
                try:
                    mod = importlib.import_module(module_path)
                    provider_name = module_path.rsplit(".", 1)[-1]
                    available = _probe_available(mod, ep, self.context)
                except (ImportError, AttributeError):
                    provider_name = module_path.rsplit(".", 1)[-1]
                    available = False

            creds_resolved = _credentials_resolved(
                password_env=password_env,
                identity_file=identity_file,
                tls_ca=tls_ca,
            )

            rows.append(
                {
                    "Host": str(host or ""),
                    "Transport": transport or "",
                    "Port": "" if port in (None, "") else str(port),
                    "Provider": provider_name,
                    "Available": "True" if available else "False",
                    "TLSRequired": "True" if require_tls else "False",
                    "CredentialsResolved": "True" if creds_resolved else "False",
                }
            )
            if available:
                available_count += 1
            else:
                unavailable_count += 1

        total = len(rows)
        # Summary row at the bottom — only appended when at least one
        # endpoint is declared, so an empty inventory stays truly empty.
        if total > 0:
            rows.append(
                {
                    "Host": "TOTAL",
                    "Transport": "",
                    "Port": "",
                    "Provider": "",
                    "Available": f"{available_count}/{total}",
                    "TLSRequired": "",
                    "CredentialsResolved": f"unavailable={unavailable_count}",
                }
            )

        return PluginResult(
            columns=columns,
            rows=rows,
            metadata={
                "total": total,
                "available": available_count,
                "unavailable": unavailable_count,
            },
        )


def _get(obj: Any, name: str, default: Any) -> Any:
    """Read ``name`` from a dict-like or attr-holding endpoint object."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _probe_available(mod: Any, ep: Any, context: Any) -> bool:
    """Best-effort :meth:`is_available` probe for a provider module.

    Scans the module for a class exposing an ``is_available`` attribute.
    Calls it directly when it behaves as a classmethod / staticmethod;
    otherwise tries to instantiate the class with the caller's endpoint
    and the active context (the shape used by
    :class:`RemoteAcquisitionProvider`). Any exception is treated as
    "unavailable" — this plugin must never raise on a misconfigured or
    partially-installed transport.
    """
    for attr in dir(mod):
        if attr.startswith("_"):
            continue
        obj = getattr(mod, attr, None)
        if not isinstance(obj, type):
            continue
        is_avail = getattr(obj, "is_available", None)
        if is_avail is None or not callable(is_avail):
            continue
        # First, try a zero-arg call (staticmethod / classmethod).
        try:
            return bool(is_avail())
        except TypeError:
            pass
        except Exception:  # noqa: BLE001
            return False
        # Fall back to instantiating the class and calling the bound
        # method. Constructor shape mirrors RemoteAcquisitionProvider —
        # ``(endpoint, *, context=...)``. If the ctor rejects this shape
        # we treat the transport as unavailable rather than guessing.
        try:
            instance = obj(ep, context=context)  # type: ignore[call-arg]
            return bool(instance.is_available())
        except Exception:  # noqa: BLE001
            continue
    return False


def _credentials_resolved(
    *,
    password_env: Any,
    identity_file: Any,
    tls_ca: Any,
) -> bool:
    """Return True iff at least one credential channel resolves to a value.

    Never reads or returns the credential itself — only checks presence.
    """
    if isinstance(password_env, str) and password_env:
        if os.environ.get(password_env):
            return True
    if identity_file:
        try:
            if Path(identity_file).exists():
                return True
        except (TypeError, ValueError, OSError):
            pass
    if tls_ca:
        try:
            if Path(tls_ca).exists():
                return True
        except (TypeError, ValueError, OSError):
            pass
    return False
