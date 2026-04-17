"""Credentials-gate test for :class:`IntelAMTProvider` (slice 21).

The provider must refuse to proceed when ``password_env`` points at an
env-var that is empty or unset. No network I/O should happen in that
path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.intel_amt import IntelAMTProvider


def test_amt_refuses_when_password_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ensure the env var definitely does not exist.
    monkeypatch.delenv("UNSET_VAR_XYZ", raising=False)

    endpoint = RemoteEndpoint(
        host="192.0.2.99",
        transport="amt",
        username="admin",
        password_env="UNSET_VAR_XYZ",
        require_tls=False,
        extra={"mode": "sol", "duration_s": "1"},
    )
    context = AnalysisContext.for_testing()
    provider = IntelAMTProvider(endpoint, context=context)

    # sol_connector / wsman_poster deliberately NOT set: if credential
    # refusal leaked past the check, this would raise something else.
    with pytest.raises(RuntimeError, match="credentials"):
        provider.acquire(
            AcquisitionTarget(hostname="192.0.2.99"),
            tmp_path / "sol.log",
            DumpFormat.RAW,
        )


def test_amt_refuses_when_password_env_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEEPVIEW_TEST_AMT_EMPTY", "")

    endpoint = RemoteEndpoint(
        host="192.0.2.99",
        transport="amt",
        username="admin",
        password_env="DEEPVIEW_TEST_AMT_EMPTY",
        require_tls=False,
    )
    context = AnalysisContext.for_testing()
    provider = IntelAMTProvider(endpoint, context=context)

    with pytest.raises(RuntimeError, match="credentials"):
        provider.acquire(
            AcquisitionTarget(hostname="192.0.2.99"),
            tmp_path / "sol.log",
            DumpFormat.RAW,
        )


def test_amt_refuses_when_password_env_unconfigured(
    tmp_path: Path,
) -> None:
    endpoint = RemoteEndpoint(
        host="192.0.2.99",
        transport="amt",
        username="admin",
        require_tls=False,
    )
    context = AnalysisContext.for_testing()
    provider = IntelAMTProvider(endpoint, context=context)

    with pytest.raises(RuntimeError, match="credentials"):
        provider.acquire(
            AcquisitionTarget(hostname="192.0.2.99"),
            tmp_path / "sol.log",
            DumpFormat.RAW,
        )
