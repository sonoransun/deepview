"""Tests for CapstoneEngine."""
from __future__ import annotations

import pytest

from deepview.disassembly.engines.capstone_engine import CapstoneEngine


class TestCapstoneEngineMetadata:
    def test_engine_name(self):
        assert CapstoneEngine.engine_name() == "Capstone"

    def test_supported_capabilities(self):
        caps = CapstoneEngine.supported_capabilities()
        assert "disassemble" in caps
        assert "strings" in caps
        assert "decompile" not in caps
        assert "cfg" not in caps
        assert "xrefs" not in caps


class TestCapstoneEngineAvailability:
    def test_is_available_returns_bool(self):
        engine = CapstoneEngine()
        assert isinstance(engine.is_available(), bool)


class TestCapstoneSession:
    @pytest.fixture
    def engine(self):
        engine = CapstoneEngine()
        if not engine.is_available():
            pytest.skip("capstone not installed")
        return engine

    def test_open_binary(self, engine, tmp_path):
        # Create a minimal binary with some x86_64 code.
        binary = tmp_path / "test.bin"
        # push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        binary.write_bytes(b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3")
        session = engine.open_binary(binary)
        assert session is not None
        info = session.binary_info
        assert info["size"] == 8
        session.close()

    def test_disassemble(self, engine, tmp_path):
        binary = tmp_path / "test.bin"
        # push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        binary.write_bytes(b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3")
        session = engine.open_binary(binary)
        result = session.disassemble(0, count=5)
        assert len(result) > 0
        assert "mnemonic" in result[0]
        assert "address" in result[0]
        session.close()

    def test_strings_extraction(self, engine, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00\x00Hello, World!\x00\x00test\x00")
        session = engine.open_binary(binary)
        strs = session.strings(min_length=4)
        values = [s["value"] for s in strs]
        assert "Hello, World!" in values
        assert "test" in values
        session.close()

    def test_decompile_raises(self, engine, tmp_path):
        from deepview.core.exceptions import ReverseEngineeringError

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\xc3")
        session = engine.open_binary(binary)
        with pytest.raises(ReverseEngineeringError, match="Ghidra or Hopper"):
            session.decompile("main")
        session.close()

    def test_xrefs_raises(self, engine, tmp_path):
        from deepview.core.exceptions import ReverseEngineeringError

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\xc3")
        session = engine.open_binary(binary)
        with pytest.raises(ReverseEngineeringError):
            session.xrefs_to(0)
        session.close()

    def test_cfg_raises(self, engine, tmp_path):
        from deepview.core.exceptions import ReverseEngineeringError

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\xc3")
        session = engine.open_binary(binary)
        with pytest.raises(ReverseEngineeringError):
            session.cfg("main")
        session.close()
