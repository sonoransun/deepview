"""Factory for constructing remote acquisition providers by transport name.

The CLI calls :func:`build_remote_provider` with the transport selector
and a fully-populated :class:`RemoteEndpoint`. We avoid auto-registering
remote providers in :meth:`MemoryManager._detect_providers` because each
one needs an endpoint to be useful — without the endpoint the class is
not instantiable.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from deepview.memory.acquisition.remote.base import (
    RemoteAcquisitionProvider,
    RemoteEndpoint,
)

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext


def build_remote_provider(
    transport: str,
    endpoint: RemoteEndpoint,
    *,
    context: AnalysisContext,
) -> RemoteAcquisitionProvider:
    """Return a concrete provider for ``transport``.

    ``transport`` is the CLI-visible selector (for example ``"ssh"``,
    ``"tcp"``, ``"agent"``, ``"dma-tb"``). Unknown selectors raise
    :class:`ValueError`.
    """
    t = transport.lower()
    if t == "ssh":
        from deepview.memory.acquisition.remote.ssh_dd import SSHDDProvider

        return SSHDDProvider(endpoint, context=context)
    if t == "tcp":
        from deepview.memory.acquisition.remote.tcp_stream import TCPStreamProvider

        return TCPStreamProvider(endpoint, context=context)
    if t == "udp":
        from deepview.memory.acquisition.remote.tcp_stream import UDPStreamProvider

        return UDPStreamProvider(endpoint, context=context)
    if t == "agent":
        from deepview.memory.acquisition.remote.network_agent import NetworkAgentProvider

        return NetworkAgentProvider(endpoint, context=context)
    if t == "lime":
        from deepview.memory.acquisition.remote.lime_remote import LiMERemoteProvider

        return LiMERemoteProvider(endpoint, context=context)
    if t in ("dma-tb", "dma_thunderbolt", "thunderbolt"):
        from deepview.memory.acquisition.remote.dma_thunderbolt import ThunderboltDMAProvider

        return ThunderboltDMAProvider(endpoint, context=context)
    if t in ("dma-pcie", "pcie"):
        from deepview.memory.acquisition.remote.dma_pcie import PCIeDMAProvider

        return PCIeDMAProvider(endpoint, context=context)
    if t in ("dma-fw", "firewire"):
        from deepview.memory.acquisition.remote.dma_firewire import FireWireDMAProvider

        return FireWireDMAProvider(endpoint, context=context)
    if t == "ipmi":
        from deepview.memory.acquisition.remote.ipmi import IPMIProvider

        return IPMIProvider(endpoint, context=context)
    if t == "amt":
        from deepview.memory.acquisition.remote.intel_amt import IntelAMTProvider

        return IntelAMTProvider(endpoint, context=context)
    raise ValueError(f"unknown remote transport: {transport}")
