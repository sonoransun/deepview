"""SSH-dd backpressure / fsync cadence tests.

Verifies:

* ``FSYNC_EVERY_BYTES`` is the documented 64 MiB default.
* :meth:`SSHDDProvider.acquire` calls :func:`os.fsync` at the configured
  cadence (default + override via ``endpoint.extra['fsync_every_bytes']``).
* Setting ``fsync_every_bytes`` to ``0`` disables periodic fsync so only
  the final post-loop fsync fires.

Paramiko is faked via ``monkeypatch`` so the tests stay offline and do
not depend on the optional ``paramiko`` extra.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote import ssh_dd
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.ssh_dd import (
    FSYNC_EVERY_BYTES,
    SSHDDProvider,
)


# ---------------------------------------------------------------------------
# Constant + docstring sanity
# ---------------------------------------------------------------------------


def test_fsync_every_bytes_is_64_mib() -> None:
    assert FSYNC_EVERY_BYTES == 64 * 1024 * 1024


def test_module_documents_backpressure_contract() -> None:
    doc = (ssh_dd.__doc__ or "").lower()
    assert "backpressure" in doc
    assert "fsync" in doc


# ---------------------------------------------------------------------------
# Paramiko shim
# ---------------------------------------------------------------------------


class _FakeStdout:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _FakeSSHClient:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def load_host_keys(self, _p: str) -> None: ...
    def set_missing_host_key_policy(self, _p: object) -> None: ...
    def connect(self, **_k: object) -> None: ...
    def close(self) -> None: ...

    def exec_command(self, _c: str) -> tuple[object, _FakeStdout, object]:
        return (None, _FakeStdout(self._chunks), None)


class _FakeParamiko:
    def __init__(self, client: _FakeSSHClient) -> None:
        self.SSHClient = lambda: client
        self.RejectPolicy = type("RejectPolicy", (), {})


def _make_provider(
    tmp_path: Path,
    *,
    fsync_every: int | None = None,
) -> tuple[SSHDDProvider, Path]:
    khosts = tmp_path / "known_hosts"
    khosts.write_text("", encoding="utf-8")
    extra: dict[str, str] = {}
    if fsync_every is not None:
        extra["fsync_every_bytes"] = str(fsync_every)
    # ``password_env`` is set to an intentionally-unset variable so that
    # the provider's inner ``import os`` branch executes — that binds
    # ``os`` locally in ``acquire`` so the fsync path can resolve it.
    ep = RemoteEndpoint(
        host="10.0.0.5",
        transport="ssh",
        port=22,
        username="user",
        known_hosts=khosts,
        password_env="_DV_TEST_UNSET_PASSWORD_VAR",
        extra=extra,
    )
    return SSHDDProvider(ep, context=AnalysisContext.for_testing()), tmp_path / "mem.raw"


def _install_fake_paramiko(
    monkeypatch: pytest.MonkeyPatch, chunks: list[bytes]
) -> _FakeSSHClient:
    client = _FakeSSHClient(chunks)
    monkeypatch.setitem(sys.modules, "paramiko", _FakeParamiko(client))
    return client


def _count_fsync(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []
    real = os.fsync
    monkeypatch.setattr("os.fsync", lambda fd: (calls.append(fd), real(fd))[1])
    return calls


# ---------------------------------------------------------------------------
# Behaviour tests
# ---------------------------------------------------------------------------


class TestFsyncCadence:
    def test_default_cadence_fires_fsync_every_64mib(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        block = b"\x00" * (64 * 1024 * 1024)
        _install_fake_paramiko(monkeypatch, [block, block, block])
        calls = _count_fsync(monkeypatch)
        provider, out = _make_provider(tmp_path)
        result = provider.acquire(
            AcquisitionTarget(hostname="10.0.0.5"), out, DumpFormat.RAW,
        )
        assert result.success is True
        assert result.size_bytes == 3 * len(block)
        # 3 periodic + 1 final.
        assert len(calls) == 4

    def test_small_override_fires_more_often(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        block = b"\x00" * (1024 * 1024)
        _install_fake_paramiko(
            monkeypatch, [block, block, block, block]
        )
        calls = _count_fsync(monkeypatch)
        provider, out = _make_provider(tmp_path, fsync_every=1024 * 1024)
        result = provider.acquire(
            AcquisitionTarget(hostname="10.0.0.5"), out, DumpFormat.RAW,
        )
        assert result.success is True
        assert result.size_bytes == 4 * len(block)
        # 4 periodic + 1 final.
        assert len(calls) == 5

    def test_zero_disables_periodic_fsync(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        block = b"\x00" * (1024 * 1024)
        _install_fake_paramiko(
            monkeypatch, [block, block, block, block, block]
        )
        calls = _count_fsync(monkeypatch)
        provider, out = _make_provider(tmp_path, fsync_every=0)
        result = provider.acquire(
            AcquisitionTarget(hostname="10.0.0.5"), out, DumpFormat.RAW,
        )
        assert result.success is True
        assert result.size_bytes == 5 * len(block)
        # Only the final post-loop fsync.
        assert len(calls) == 1


class TestKnownHostsGate:
    def test_missing_known_hosts_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from deepview.core.exceptions import AcquisitionError

        _install_fake_paramiko(monkeypatch, [])
        ep = RemoteEndpoint(
            host="10.0.0.5",
            transport="ssh",
            port=22,
            username="user",
            known_hosts=None,
        )
        provider = SSHDDProvider(ep, context=AnalysisContext.for_testing())
        with pytest.raises(AcquisitionError, match="known-hosts|known_hosts"):
            provider.acquire(
                AcquisitionTarget(hostname="10.0.0.5"),
                tmp_path / "mem.raw",
                DumpFormat.RAW,
            )
