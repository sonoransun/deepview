"""Tests for the ``extracted_keys`` built-in plugin."""
from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest

from deepview.core.context import AnalysisContext
from deepview.core.types import LayerMetadata, ScanResult
from deepview.detection.encryption_keys import EncryptionKeyScanner
from deepview.interfaces.layer import DataLayer
from deepview.interfaces.plugin import PluginResult, Requirement
from deepview.plugins.builtin.extracted_keys import ExtractedKeysPlugin


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
        return LayerMetadata(name=self._name, os="linux")


def _build_high_entropy_buffer(seed: int = 0x1337) -> bytes:
    """Build a buffer that will produce at least one AES key-schedule match.

    The real ``EncryptionKeyScanner.scan_aes_keys`` accepts any 176/240-byte
    window whose first round key is non-zero, non-uniform, and whose overall
    Shannon entropy exceeds 6 bits/byte — bytes drawn from ``os.urandom``
    trivially satisfy all three predicates.
    """
    # Use a deterministic-but-random-ish buffer so the test is stable.
    # ``os.urandom`` is fine here because we only assert on "at least one"
    # finding, which is overwhelmingly likely regardless of the draw.
    prefix = b"\x00" * 256
    body = os.urandom(512)
    suffix = b"\x00" * 256
    return prefix + body + suffix


@pytest.fixture()
def context_with_layer() -> AnalysisContext:
    ctx = AnalysisContext.for_testing()
    ctx.layers.register(
        "mem0", _MemoryDataLayer(_build_high_entropy_buffer(), name="mem0")
    )
    return ctx


class TestExtractedKeysPluginMetadata:
    def test_requirements_declared(self) -> None:
        reqs = ExtractedKeysPlugin.get_requirements()
        names = {r.name for r in reqs}
        assert {"layer_name", "confidence_threshold", "key_types"}.issubset(
            names
        )
        by_name = {r.name: r for r in reqs}
        assert by_name["layer_name"].required is True
        assert by_name["confidence_threshold"].default == pytest.approx(0.7)
        assert by_name["key_types"].default == "all"
        for req in reqs:
            assert isinstance(req, Requirement)

    def test_registered(self) -> None:
        from deepview.plugins.base import get_registered_plugins

        assert "extracted_keys" in get_registered_plugins()


class TestExtractedKeysPluginExecution:
    def test_missing_layer_name_returns_error_metadata(
        self, context_with_layer: AnalysisContext
    ) -> None:
        plugin = ExtractedKeysPlugin(context_with_layer, config={})
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert result.rows == []
        assert "error" in result.metadata

    def test_unknown_layer_returns_error_metadata(
        self, context_with_layer: AnalysisContext
    ) -> None:
        plugin = ExtractedKeysPlugin(
            context_with_layer, config={"layer_name": "nope"}
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        assert result.rows == []
        assert "error" in result.metadata

    def test_finds_at_least_one_aes_key(
        self, context_with_layer: AnalysisContext
    ) -> None:
        plugin = ExtractedKeysPlugin(
            context_with_layer,
            config={
                "layer_name": "mem0",
                "confidence_threshold": 0.5,
                "key_types": "all",
            },
        )
        result = plugin.run()
        assert isinstance(result, PluginResult)
        # Our high-entropy body reliably produces AES matches.
        assert result.rows, (
            "Expected at least one key finding on high-entropy buffer; "
            f"got metadata={result.metadata!r}"
        )
        for row in result.rows:
            assert set(row.keys()) == set(result.columns)
            assert row["KeyType"].startswith("aes") or row["KeyType"] in {
                "rsa",
                "bitlocker",
                "dm_crypt",
            }
            assert len(row["KeyDataPreview"]) <= 32  # 16 bytes hex == 32 chars
        # Artifacts were recorded.
        artifacts = context_with_layer.artifacts.get("encryption_keys")
        assert len(artifacts) == len(result.rows)
        for art in artifacts:
            assert art["layer"] == "mem0"
            assert "key_type" in art
            assert "offset" in art

    def test_high_threshold_filters_out_findings(
        self, context_with_layer: AnalysisContext
    ) -> None:
        plugin = ExtractedKeysPlugin(
            context_with_layer,
            config={
                "layer_name": "mem0",
                "confidence_threshold": 0.99,
                "key_types": "all",
            },
        )
        result = plugin.run()
        # Scanner ceilings confidence at 0.85 for AES / 0.75 for RSA / 0.70
        # for BitLocker — a 0.99 threshold rejects everything.
        assert result.rows == []
        # But the scanner still ran (bytes_scanned reports work done).
        assert result.metadata.get("bytes_scanned", 0) > 0

    def test_key_type_filter_respected(
        self, context_with_layer: AnalysisContext
    ) -> None:
        plugin = ExtractedKeysPlugin(
            context_with_layer,
            config={
                "layer_name": "mem0",
                "confidence_threshold": 0.5,
                "key_types": "rsa",  # exclude AES; buffer has no RSA pattern
            },
        )
        result = plugin.run()
        # All AES findings filtered out by the key_types allow-list.
        for row in result.rows:
            assert row["KeyType"] == "rsa"
