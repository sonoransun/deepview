"""Tests for DisassemblyManager."""
from __future__ import annotations

import pytest

from deepview.core.exceptions import EngineNotAvailableError
from deepview.disassembly.manager import DisassemblyManager


class TestDisassemblyManager:
    def test_available_engines_returns_list(self, context):
        dm = DisassemblyManager(context)
        assert isinstance(dm.available_engines, list)

    def test_get_engine_invalid_name_raises(self, context):
        dm = DisassemblyManager(context)
        with pytest.raises(EngineNotAvailableError, match="nonexistent"):
            dm.get_engine("nonexistent")

    def test_get_engine_auto_returns_something_or_raises(self, context):
        dm = DisassemblyManager(context)
        if dm.available_engines:
            engine = dm.get_engine("auto")
            assert engine is not None
            assert engine.is_available()
        else:
            with pytest.raises(EngineNotAvailableError):
                dm.get_engine("auto")

    def test_close_all_clears_sessions(self, context):
        dm = DisassemblyManager(context)
        dm.close_all()
        assert len(dm._sessions) == 0
