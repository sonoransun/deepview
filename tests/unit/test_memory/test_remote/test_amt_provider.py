"""Unit tests for :class:`IntelAMTProvider` (slice 21, SOL mode).

Uses the instance-level ``sol_connector`` hook on the provider to inject
a deterministic byte stream without touching a real AMT endpoint. The
provider's WS-MAN enablement call is also replaced via ``wsman_poster``
so the test runs offline.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    RemoteAcquisitionCompletedEvent,
    RemoteAcquisitionStartedEvent,
)
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.intel_amt import IntelAMTProvider


def test_amt_sol_records_stream_from_connector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEEPVIEW_TEST_AMT_PW", "p@ssw0rd")

    payload = (
        b"U-Boot 2021.07 (Intel AMT SOL) console\r\n"
        b"login: root\r\nPassword: \r\n# "
        b"dd if=/dev/mem bs=1M | nc 10.0.0.1 5555\r\n"
    )

    def fake_sol(
        host: str, port: int, username: str, password: str, duration_s: float
    ) -> bytes:
        assert host == "192.0.2.50"
        assert port == 16995
        assert username == "admin"
        assert password == "p@ssw0rd"
        assert duration_s == 2.0
        return payload

    def fake_wsman(
        *,
        url: str,
        envelope: str,
        username: str,
        password: str,
        action: str,
        resource_uri: str,
    ) -> bytes:
        assert url.endswith("/wsman")
        assert "AMT_RedirectionService" in resource_uri
        return b"<ok/>"

    endpoint = RemoteEndpoint(
        host="192.0.2.50",
        transport="amt",
        port=16993,
        username="admin",
        password_env="DEEPVIEW_TEST_AMT_PW",
        require_tls=False,
        extra={"mode": "sol", "duration_s": "2"},
    )
    context = AnalysisContext.for_testing()
    started: list[RemoteAcquisitionStartedEvent] = []
    completed: list[RemoteAcquisitionCompletedEvent] = []
    context.events.subscribe(RemoteAcquisitionStartedEvent, started.append)
    context.events.subscribe(RemoteAcquisitionCompletedEvent, completed.append)

    provider = IntelAMTProvider(endpoint, context=context)
    provider.sol_connector = fake_sol
    provider.wsman_poster = fake_wsman

    output = tmp_path / "sol.log"
    result = provider.acquire(
        AcquisitionTarget(hostname="192.0.2.50"), output, DumpFormat.RAW
    )

    assert result.success is True
    assert result.output_path == output
    assert result.size_bytes == len(payload)
    assert output.read_bytes() == payload
    assert result.hash_sha256  # non-empty hex digest
    assert len(started) == 1
    assert len(completed) == 1
    assert completed[0].size_bytes == len(payload)


def test_amt_ide_redirect_writes_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEEPVIEW_TEST_AMT_PW", "hunter2")
    calls: list[tuple[str, str]] = []

    def fake_wsman(
        *,
        url: str,
        envelope: str,
        username: str,
        password: str,
        action: str,
        resource_uri: str,
    ) -> bytes:
        calls.append((action, resource_uri))
        return b"<ok/>"

    endpoint = RemoteEndpoint(
        host="192.0.2.77",
        transport="amt",
        username="admin",
        password_env="DEEPVIEW_TEST_AMT_PW",
        require_tls=False,
        extra={"mode": "ide-redirect", "iso_url": "https://example.invalid/forensic.iso"},
    )
    context = AnalysisContext.for_testing()
    provider = IntelAMTProvider(endpoint, context=context)
    provider.wsman_poster = fake_wsman

    output = tmp_path / "ide.json"
    result = provider.acquire(
        AcquisitionTarget(hostname="192.0.2.77"), output, DumpFormat.RAW
    )

    assert result.success is True
    assert output.exists()
    import json as _json

    manifest = _json.loads(output.read_text(encoding="utf-8"))
    assert manifest["mode"] == "ide-redirect"
    assert manifest["iso_url"] == "https://example.invalid/forensic.iso"
    # Two WS-MAN calls: set boot source + reboot.
    assert len(calls) == 2
    assert any("Put" in action for action, _ in calls)
    assert any("RequestStateChange" in action for action, _ in calls)
