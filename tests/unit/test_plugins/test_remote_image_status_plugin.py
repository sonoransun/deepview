"""Tests for the :class:`RemoteImageStatusPlugin` built-in plugin."""
from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from deepview.core.context import AnalysisContext
from deepview.interfaces.plugin import PluginResult
from deepview.plugins.builtin.remote_image_status import RemoteImageStatusPlugin


@pytest.fixture()
def context() -> AnalysisContext:
    return AnalysisContext.for_testing()


def _force_set(obj: Any, name: str, value: Any) -> None:
    """Install an attribute on a pydantic settings object without validation.

    ``DeepViewConfig`` is a pydantic ``BaseSettings`` that rejects unknown
    field assignment via normal ``setattr``. The plugin only reads the
    attribute via ``getattr``, so bypassing model validation with
    ``object.__setattr__`` gives the test a clean seam.
    """
    object.__setattr__(obj, name, value)


class TestRemoteImageStatusEmpty:
    """Behavior when no endpoints are configured."""

    def test_no_endpoints_returns_zero_metadata(self, context: AnalysisContext) -> None:
        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()
        assert isinstance(result, PluginResult)
        # Either the subsystem isn't shipped (graceful error) or the
        # subsystem is shipped but no endpoints configured.
        if "error" in result.metadata:
            assert "not available" in result.metadata["error"].lower()
            assert result.metadata.get("total", 0) == 0
        else:
            assert result.metadata.get("total", 0) == 0
            assert result.metadata.get("available", 0) == 0
            assert result.metadata.get("unavailable", 0) == 0

    def test_columns_are_declared(self, context: AnalysisContext) -> None:
        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()
        assert result.columns == [
            "Host",
            "Transport",
            "Port",
            "Provider",
            "Available",
            "TLSRequired",
            "CredentialsResolved",
        ]


class TestRemoteImageStatusSubsystemMissing:
    """The plugin must degrade gracefully when slice 19 isn't shipped."""

    def test_subsystem_missing_returns_graceful_metadata(
        self,
        context: AnalysisContext,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import importlib as _importlib

        real_import = _importlib.import_module

        def _raise_for_factory(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "deepview.memory.acquisition.remote.factory":
                raise ModuleNotFoundError("No module named remote.factory (test)")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(
            "deepview.plugins.builtin.remote_image_status.importlib.import_module",
            _raise_for_factory,
        )

        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert result.rows == []
        assert "error" in result.metadata
        assert "not available" in result.metadata["error"].lower()
        assert result.metadata["total"] == 0


class TestRemoteImageStatusWithEndpoint:
    """Populated-endpoint behavior, using a stub remote subsystem."""

    def _install_fake_factory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Install stub factory + stub transport module, both exposing is_available."""
        fake_factory = types.ModuleType(
            "deepview.memory.acquisition.remote.factory"
        )

        class _FakeProvider:
            @staticmethod
            def is_available() -> bool:
                return True

        def build_remote_provider(transport: str, endpoint: Any, *, context: Any) -> Any:
            return _FakeProvider()

        fake_factory.build_remote_provider = build_remote_provider  # type: ignore[attr-defined]
        fake_factory._FakeProvider = _FakeProvider  # type: ignore[attr-defined]
        monkeypatch.setitem(
            sys.modules,
            "deepview.memory.acquisition.remote.factory",
            fake_factory,
        )

        # Override the transport-module table so the probe lands on our
        # stub module whose class exposes a ``True`` is_available —
        # independent of whether paramiko is actually installed.
        fake_ssh = types.ModuleType("deepview_test_fake_ssh")
        fake_ssh.FakeSSH = _FakeProvider  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "deepview_test_fake_ssh", fake_ssh)

        fake_agent = types.ModuleType("deepview_test_fake_agent")
        fake_agent.FakeAgent = _FakeProvider  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "deepview_test_fake_agent", fake_agent)

        import deepview.plugins.builtin.remote_image_status as mod

        monkeypatch.setitem(mod._TRANSPORT_MODULES, "ssh", "deepview_test_fake_ssh")
        monkeypatch.setitem(mod._TRANSPORT_MODULES, "agent", "deepview_test_fake_agent")

    def test_fake_endpoint_reports_available(
        self,
        context: AnalysisContext,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._install_fake_factory(monkeypatch)

        # Inject a single fake endpoint on the pydantic-settings config.
        endpoint = {
            "host": "10.0.0.9",
            "transport": "ssh",
            "port": 22,
            "password_env": None,
            "identity_file": None,
            "tls_ca": None,
            "require_tls": False,
        }
        _force_set(context.config, "remote_endpoints", [endpoint])

        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()
        assert isinstance(result, PluginResult)

        # Strip the trailing summary row.
        data_rows = [r for r in result.rows if r.get("Host") != "TOTAL"]
        assert len(data_rows) == 1
        row = data_rows[0]
        assert row["Host"] == "10.0.0.9"
        assert row["Transport"] == "ssh"
        assert row["Port"] == "22"
        assert row["TLSRequired"] == "False"
        assert row["CredentialsResolved"] == "False"
        # With the stubbed ssh transport module, is_available() returns
        # True deterministically regardless of whether paramiko is on the
        # host.
        assert row["Available"] == "True"

        assert result.metadata["total"] == 1
        assert result.metadata["available"] == 1
        assert result.metadata["unavailable"] == 0

        # Summary row formatting.
        summary = [r for r in result.rows if r.get("Host") == "TOTAL"]
        assert len(summary) == 1

    def test_credentials_resolved_via_env(
        self,
        context: AnalysisContext,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._install_fake_factory(monkeypatch)

        monkeypatch.setenv("DV_TEST_REMOTE_PW", "hunter2")
        endpoint = {
            "host": "10.0.0.9",
            "transport": "ssh",
            "port": 22,
            "password_env": "DV_TEST_REMOTE_PW",
            "identity_file": None,
            "tls_ca": None,
            "require_tls": True,
        }
        _force_set(context.config, "remote_endpoints", [endpoint])

        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()

        data_rows = [r for r in result.rows if r.get("Host") != "TOTAL"]
        assert len(data_rows) == 1
        row = data_rows[0]
        assert row["CredentialsResolved"] == "True"
        assert row["TLSRequired"] == "True"

        # The credential value itself must never appear in any row or
        # metadata. This is a security-hardening assertion.
        joined = repr(result.rows) + repr(result.metadata)
        assert "hunter2" not in joined

    def test_credentials_resolved_via_file(
        self,
        context: AnalysisContext,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        self._install_fake_factory(monkeypatch)

        ca_file = tmp_path / "ca.pem"
        ca_file.write_text("-----BEGIN FAKE CA-----\n")

        endpoint = {
            "host": "10.0.0.9",
            "transport": "agent",
            "port": 443,
            "password_env": None,
            "identity_file": None,
            "tls_ca": str(ca_file),
            "require_tls": True,
        }
        _force_set(context.config, "remote_endpoints", [endpoint])

        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()

        data_rows = [r for r in result.rows if r.get("Host") != "TOTAL"]
        assert len(data_rows) == 1
        assert data_rows[0]["CredentialsResolved"] == "True"

    def test_unknown_transport_reports_unavailable(
        self,
        context: AnalysisContext,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._install_fake_factory(monkeypatch)

        endpoint = {
            "host": "10.0.0.9",
            "transport": "carrier-pigeon",
            "port": 0,
        }
        _force_set(context.config, "remote_endpoints", [endpoint])

        plugin = RemoteImageStatusPlugin(context, config={})
        result = plugin.run()

        data_rows = [r for r in result.rows if r.get("Host") != "TOTAL"]
        assert len(data_rows) == 1
        assert data_rows[0]["Available"] == "False"
        assert data_rows[0]["Provider"] == "<unknown>"
        assert result.metadata["available"] == 0
        assert result.metadata["unavailable"] == 1
