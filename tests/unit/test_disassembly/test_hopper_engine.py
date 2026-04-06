"""Tests for HopperEngine."""
from __future__ import annotations

import pytest

from deepview.disassembly.engines.hopper import HopperEngine


class TestHopperEngineMetadata:
    def test_engine_name(self):
        assert HopperEngine.engine_name() == "Hopper"

    def test_supported_capabilities(self):
        caps = HopperEngine.supported_capabilities()
        assert "disassemble" in caps
        assert "decompile" in caps
        assert "functions" in caps
        assert "xrefs" not in caps  # Hopper CLI doesn't support xrefs


class TestHopperEngineAvailability:
    def test_is_available_returns_bool(self):
        engine = HopperEngine()
        assert isinstance(engine.is_available(), bool)

    def test_open_binary_raises_when_unavailable(self, tmp_path):
        engine = HopperEngine()
        if engine.is_available():
            pytest.skip("Hopper is installed; cannot test unavailable path")
        from deepview.core.exceptions import EngineNotAvailableError

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\xc3")
        with pytest.raises(EngineNotAvailableError):
            engine.open_binary(binary)


@pytest.mark.requires_hopper
class TestHopperSessionIntegration:
    """Integration tests requiring Hopper installation."""

    def test_open_and_list_functions(self, context, tmp_path):
        engine = HopperEngine(context.config.disassembly)
        if not engine.is_available():
            pytest.skip("Hopper not available")
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3")
        session = engine.open_binary(binary)
        funcs = session.functions()
        assert isinstance(funcs, list)
        session.close()
