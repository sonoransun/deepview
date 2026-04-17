"""Sanity checks for :class:`RemoteEndpoint` and the authorization gate."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.exceptions import AcquisitionError
from deepview.core.types import AcquisitionTarget
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.network_agent import NetworkAgentProvider


def test_endpoint_is_dumb_dataclass() -> None:
    """The dataclass must accept any combination at construction."""
    ep = RemoteEndpoint(
        host="203.0.113.5",
        transport="grpc",
        port=None,
        username=None,
        identity_file=None,
        password_env=None,
        known_hosts=None,
        tls_ca=None,
        require_tls=True,
    )
    assert ep.host == "203.0.113.5"
    assert ep.require_tls is True
    assert ep.extra == {}


def test_endpoint_extra_and_indirection_only() -> None:
    """Credentials are *references*, never raw values."""
    ep = RemoteEndpoint(
        host="example.test",
        transport="ssh",
        username="root",
        password_env="MY_PASS_VAR",
        identity_file=Path("/tmp/id_ed25519"),
        extra={"source": "/proc/kcore"},
    )
    # No password attribute — only env var name.
    assert ep.password_env == "MY_PASS_VAR"
    assert ep.extra["source"] == "/proc/kcore"
    # frozen => mutation forbidden
    with pytest.raises(Exception):
        ep.host = "other"  # type: ignore[misc]


def test_require_tls_without_ca_aborts_in_agent() -> None:
    """The require_tls + tls_ca=None combination is caught at acquire() time."""
    ep = RemoteEndpoint(
        host="127.0.0.1",
        transport="grpc",
        port=1,
        tls_ca=None,
        require_tls=True,
    )
    context = AnalysisContext.for_testing()
    provider = NetworkAgentProvider(ep, context=context)
    with pytest.raises(AcquisitionError, match="tls_ca"):
        provider.acquire(AcquisitionTarget(hostname=ep.host), Path("/tmp/_unused_dv.bin"))
