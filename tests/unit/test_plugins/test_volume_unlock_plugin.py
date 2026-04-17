"""Tests for the ``volume_unlock`` built-in plugin."""
from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer
from deepview.interfaces.plugin import PluginResult, Requirement
from deepview.plugins.builtin.volume_unlock import VolumeUnlockPlugin


class _MemoryDataLayer(DataLayer):
    """Minimal in-memory DataLayer for unit tests."""

    def __init__(self, data: bytes, name: str = "mem") -> None:
        self._data = bytes(data)
        self._name = name

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = min(offset + length, len(self._data))
        out = self._data[offset:end] if offset >= 0 else b""
        if pad and len(out) < length:
            out = out + b"\x00" * (length - len(out))
        return out

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and offset + length <= len(self._data)

    def scan(
        self, scanner: object, progress_callback: Callable | None = None
    ) -> Iterator[ScanResult]:
        yield from ()

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return max(0, len(self._data) - 1)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name=self._name)


@pytest.fixture()
def context() -> AnalysisContext:
    # The orchestrator may touch ``context.offload`` indirectly only if
    # a passphrase candidate is tried — the plugin never does that, so
    # no stub is needed.
    return AnalysisContext.for_testing()


class TestVolumeUnlockPluginMetadata:
    def test_requirements_declared(self) -> None:
        reqs = VolumeUnlockPlugin.get_requirements()
        assert isinstance(reqs, list)
        names = {r.name for r in reqs}
        assert {"layers", "scan_keys"}.issubset(names)
        for req in reqs:
            assert isinstance(req, Requirement)
            assert req.required is False

    def test_registered_in_plugin_registry(self) -> None:
        # Importing the builtin package is what triggers @register_plugin;
        # the decorator runs at volume_unlock import time (already done by
        # this test module's import above).
        from deepview.plugins.base import get_registered_plugins

        assert "volume_unlock" in get_registered_plugins()


class TestVolumeUnlockPluginExecution:
    def test_empty_registry_returns_empty_result(
        self, context: AnalysisContext
    ) -> None:
        plugin = VolumeUnlockPlugin(
            context, config={"layers": "all", "scan_keys": False}
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert result.rows == []
        # Columns are always stable regardless of whether containers matched.
        assert result.columns == [
            "Layer",
            "Format",
            "Cipher",
            "CandidateKeys",
            "DataOffset",
            "DataLength",
        ]

    def test_tiny_in_memory_layer(self, context: AnalysisContext) -> None:
        # Register a tiny buffer; we don't assert on the number of rows
        # because whether any registered unlocker matches plain bytes
        # depends on which slice adapters (LUKS/VeraCrypt/...) are
        # importable. The plugin must simply return a PluginResult.
        context.layers.register("disk", _MemoryDataLayer(b"\x00" * 2048))

        plugin = VolumeUnlockPlugin(
            context, config={"layers": "all", "scan_keys": False}
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        # Every row has the right shape when present.
        for row in result.rows:
            assert set(row.keys()) == set(result.columns)
        # Metadata surfaces the diagnostic counts.
        assert "layers_scanned" in result.metadata
        assert result.metadata["layers_scanned"] == 1
        assert "unlockers_available" in result.metadata

    def test_explicit_layer_filter(self, context: AnalysisContext) -> None:
        context.layers.register("a", _MemoryDataLayer(b"\x11" * 512, name="a"))
        context.layers.register("b", _MemoryDataLayer(b"\x22" * 512, name="b"))

        plugin = VolumeUnlockPlugin(
            context,
            config={"layers": "a", "scan_keys": False},
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        # Only one layer was considered even though two are registered.
        assert result.metadata["layers_scanned"] == 1

    def test_unknown_layer_name_is_skipped(
        self, context: AnalysisContext
    ) -> None:
        plugin = VolumeUnlockPlugin(
            context,
            config={"layers": "does_not_exist", "scan_keys": False},
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert result.metadata["layers_scanned"] == 0
        assert result.rows == []
