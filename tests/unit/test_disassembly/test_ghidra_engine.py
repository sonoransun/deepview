"""Tests for GhidraEngine."""
from __future__ import annotations

import pytest

from deepview.disassembly.engines.ghidra import GhidraEngine


class TestGhidraEngineMetadata:
    def test_engine_name(self):
        assert GhidraEngine.engine_name() == "Ghidra"

    def test_supported_capabilities(self):
        caps = GhidraEngine.supported_capabilities()
        assert "disassemble" in caps
        assert "decompile" in caps
        assert "cfg" in caps
        assert "xrefs" in caps
        assert "functions" in caps


class TestGhidraEngineAvailability:
    def test_is_available_returns_bool(self):
        engine = GhidraEngine()
        assert isinstance(engine.is_available(), bool)

    def test_open_binary_raises_when_unavailable(self, tmp_path):
        engine = GhidraEngine()
        if engine.is_available():
            pytest.skip("Ghidra is installed; cannot test unavailable path")
        from deepview.core.exceptions import EngineNotAvailableError

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\xc3")
        with pytest.raises(EngineNotAvailableError):
            engine.open_binary(binary)


@pytest.mark.requires_ghidra
class TestGhidraSessionIntegration:
    """Integration tests requiring Ghidra installation."""

    def test_open_and_list_functions(self, context, tmp_path):
        engine = GhidraEngine(context.config.disassembly)
        if not engine.is_available():
            pytest.skip("Ghidra not available")
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3")
        session = engine.open_binary(binary)
        funcs = session.functions()
        assert isinstance(funcs, list)
        session.close()
