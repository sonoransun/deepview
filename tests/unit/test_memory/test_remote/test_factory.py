"""Tests for :func:`build_remote_provider`.

Targets ``deepview.memory.acquisition.remote.factory.build_remote_provider``.
The factory dispatches transport names to concrete providers and raises
:class:`ValueError` on unknown selectors. Every provider's implementation
module is imported lazily so a core install without the ``paramiko`` /
``pywinrm`` / ``leechcore`` extras still imports the factory module.
"""
from __future__ import annotations

import importlib

import pytest

from deepview.memory.acquisition.remote.base import (
    RemoteAcquisitionProvider,
    RemoteEndpoint,
)
from deepview.memory.acquisition.remote.factory import build_remote_provider


# ---------------------------------------------------------------------------
# Known-transport dispatch
# ---------------------------------------------------------------------------


def test_ssh_transport_returns_sshdd_provider(context) -> None:
    """'ssh' → SSHDDProvider (import-gated on paramiko when present)."""
    endpoint = RemoteEndpoint(host="10.0.0.1", transport="ssh")
    try:
        provider = build_remote_provider("ssh", endpoint, context=context)
    except ImportError:
        pytest.skip("paramiko not installed — SSHDDProvider not importable")
        return

    from deepview.memory.acquisition.remote.ssh_dd import SSHDDProvider

    assert isinstance(provider, SSHDDProvider)
    assert isinstance(provider, RemoteAcquisitionProvider)
    assert provider.endpoint is endpoint


def test_tcp_transport_returns_tcpstream_provider(context) -> None:
    endpoint = RemoteEndpoint(host="10.0.0.2", transport="tcp")
    provider = build_remote_provider("tcp", endpoint, context=context)

    from deepview.memory.acquisition.remote.tcp_stream import TCPStreamProvider

    assert isinstance(provider, TCPStreamProvider)
    assert provider.endpoint is endpoint


def test_unknown_transport_raises_valueerror(context) -> None:
    """Unknown transport → ValueError whose message names the selector."""
    endpoint = RemoteEndpoint(host="10.0.0.3", transport="ssh")
    with pytest.raises(ValueError) as excinfo:
        build_remote_provider("unknown-transport", endpoint, context=context)
    assert "unknown-transport" in str(excinfo.value)


def test_transport_name_is_case_insensitive(context) -> None:
    """Factory lowercases the transport selector."""
    endpoint = RemoteEndpoint(host="10.0.0.4", transport="tcp")
    provider = build_remote_provider("TCP", endpoint, context=context)

    from deepview.memory.acquisition.remote.tcp_stream import TCPStreamProvider

    assert isinstance(provider, TCPStreamProvider)


def test_dma_aliases_resolve_to_same_class(context) -> None:
    """Both 'dma-tb' and 'thunderbolt' select the same provider class."""
    endpoint = RemoteEndpoint(host="10.0.0.5", transport="dma")
    try:
        p1 = build_remote_provider("dma-tb", endpoint, context=context)
        p2 = build_remote_provider("thunderbolt", endpoint, context=context)
    except ImportError:
        pytest.skip("Thunderbolt DMA extras not installed")
        return
    assert type(p1) is type(p2)


# ---------------------------------------------------------------------------
# Module-level registration stability across re-imports
# ---------------------------------------------------------------------------


def test_factory_module_is_stable_across_reimport() -> None:
    """Re-importing the factory module preserves the public API."""
    import deepview.memory.acquisition.remote.factory as factory_mod
    before = factory_mod.build_remote_provider

    reloaded = importlib.reload(factory_mod)
    after = reloaded.build_remote_provider

    # After reload the function object changes, but both should be
    # callable and share the same qualified name.
    assert callable(before)
    assert callable(after)
    assert before.__qualname__ == after.__qualname__ == "build_remote_provider"


# ---------------------------------------------------------------------------
# RemoteEndpoint defaults
# ---------------------------------------------------------------------------


def test_remote_endpoint_requires_tls_by_default() -> None:
    """RemoteEndpoint.require_tls defaults to True (CLI safety gate)."""
    ep = RemoteEndpoint(host="host.example", transport="tcp")
    assert ep.require_tls is True


def test_remote_endpoint_allows_require_tls_false_via_explicit_kw() -> None:
    """The dataclass allows require_tls=False; CLI enforces --insecure-transport."""
    ep = RemoteEndpoint(
        host="host.example", transport="tcp", require_tls=False
    )
    assert ep.require_tls is False


def test_remote_endpoint_is_frozen() -> None:
    """RemoteEndpoint is a frozen dataclass — attribute assignment refused."""
    ep = RemoteEndpoint(host="host.example", transport="tcp")
    with pytest.raises(Exception):
        ep.host = "evil.example"  # type: ignore[misc]
