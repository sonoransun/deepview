"""Unit tests for :class:`IPMIMemoryProvider` (slice 21).

Mocks out ``pyipmi.interfaces.create_interface`` and
``pyipmi.create_connection`` so no real BMC is required. Only the
default SEL-dump mode is exercised; firmware mode is vendor-specific
and covered separately in integration tests.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pyipmi = pytest.importorskip("pyipmi", reason="python-ipmi extra not installed")
pyipmi_interfaces = pytest.importorskip(
    "pyipmi.interfaces", reason="python-ipmi.interfaces not installed"
)

from deepview.core.context import AnalysisContext  # noqa: E402
from deepview.core.types import AcquisitionTarget, DumpFormat  # noqa: E402
from deepview.memory.acquisition.remote.base import RemoteEndpoint  # noqa: E402
from deepview.memory.acquisition.remote.ipmi import IPMIMemoryProvider  # noqa: E402


class _FakeSELRecord:
    def __init__(
        self,
        *,
        record_id: int,
        type: int,
        timestamp: int,
        sensor_type: int,
        sensor_number: int,
        event_type: int,
        event_direction: str,
        event_data: bytes,
    ) -> None:
        self.record_id = record_id
        self.type = type
        self.timestamp = timestamp
        self.sensor_type = sensor_type
        self.sensor_number = sensor_number
        self.event_type = event_type
        self.event_direction = event_direction
        self.event_data = event_data


def _install_fake_pyipmi(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace ``pyipmi.interfaces.create_interface`` + ``create_connection``
    with MagicMocks and return the fake connection. The fake connection's
    ``get_sel_iterator`` yields three synthetic records.
    """
    records = [
        _FakeSELRecord(
            record_id=1,
            type=2,
            timestamp=1_700_000_000,
            sensor_type=0x01,
            sensor_number=0x04,
            event_type=0x6F,
            event_direction="assert",
            event_data=b"\x01\x02\x03",
        ),
        _FakeSELRecord(
            record_id=2,
            type=2,
            timestamp=1_700_000_060,
            sensor_type=0x07,
            sensor_number=0x10,
            event_type=0x01,
            event_direction="deassert",
            event_data=b"\xaa",
        ),
        _FakeSELRecord(
            record_id=3,
            type=2,
            timestamp=1_700_000_120,
            sensor_type=0x1F,
            sensor_number=0x01,
            event_type=0x6F,
            event_direction="assert",
            event_data=b"",
        ),
    ]

    fake_ipmi = MagicMock()
    fake_ipmi.get_sel_iterator.return_value = iter(records)
    fake_ipmi.session = MagicMock()

    monkeypatch.setattr(
        pyipmi_interfaces,
        "create_interface",
        lambda *args, **kwargs: MagicMock(name="interface"),
        raising=False,
    )
    monkeypatch.setattr(
        sys.modules["pyipmi"],
        "create_connection",
        lambda interface: fake_ipmi,
        raising=False,
    )
    # ``pyipmi.Target`` is called with 0x20; we don't care about the result.
    if not hasattr(sys.modules["pyipmi"], "Target"):
        sys.modules["pyipmi"].Target = (  # type: ignore[attr-defined]
            lambda addr: types.SimpleNamespace(addr=addr)
        )
    return fake_ipmi


def test_ipmi_sel_dump_produces_jsonl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEEPVIEW_TEST_IPMI_PW", "s3cr3t")
    fake = _install_fake_pyipmi(monkeypatch)

    endpoint = RemoteEndpoint(
        host="10.0.0.42",
        transport="ipmi",
        port=623,
        username="ADMIN",
        password_env="DEEPVIEW_TEST_IPMI_PW",
        extra={"mode": "sel"},
    )
    context = AnalysisContext.for_testing()
    provider = IPMIMemoryProvider(endpoint, context=context)

    output = tmp_path / "sel.jsonl"
    result = provider.acquire(
        AcquisitionTarget(hostname="10.0.0.42"), output, DumpFormat.RAW
    )

    assert result.success is True
    assert result.output_path == output
    assert result.size_bytes > 0
    assert output.exists()

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    decoded: list[dict[str, Any]] = [json.loads(line) for line in lines]
    assert decoded[0]["record_id"] == 1
    assert decoded[0]["event_data"] == "010203"  # bytes -> hex
    assert decoded[2]["sensor_type"] == 0x1F
    # Every record should be JSON-serialisable and carry the repr fallback.
    for entry in decoded:
        assert "repr" in entry

    # Session lifecycle: establish + close must have fired.
    fake.session.establish.assert_called_once()
    fake.session.close.assert_called_once()


def test_ipmi_rejects_empty_password_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DEEPVIEW_TEST_IPMI_EMPTY", raising=False)
    endpoint = RemoteEndpoint(
        host="10.0.0.42",
        transport="ipmi",
        username="ADMIN",
        password_env="DEEPVIEW_TEST_IPMI_EMPTY",
        extra={"mode": "sel"},
    )
    context = AnalysisContext.for_testing()
    provider = IPMIMemoryProvider(endpoint, context=context)

    with pytest.raises(RuntimeError, match="credentials"):
        provider.acquire(
            AcquisitionTarget(hostname="10.0.0.42"),
            tmp_path / "sel.jsonl",
            DumpFormat.RAW,
        )
