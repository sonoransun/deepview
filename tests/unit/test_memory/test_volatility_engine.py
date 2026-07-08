"""Tests for the Volatility 3 engine wrapper's graceful-degradation contract."""
from __future__ import annotations

import pytest

from deepview.memory.analysis.volatility import VolatilityEngine


class TestVolatilityUnavailable:
    def test_graceful_when_unavailable(self):
        eng = VolatilityEngine()
        if eng.is_available():
            pytest.skip("volatility3 is installed; unavailable path not exercised")
        # list_plugins must not raise (the old code sorted unorderable classes).
        assert eng.list_plugins() == []
        with pytest.raises(RuntimeError):
            eng.run_plugin("pslist", None)
        with pytest.raises(RuntimeError):
            eng.open_image(__import__("pathlib").Path("/nonexistent.raw"))

    def test_engine_name(self):
        assert VolatilityEngine.engine_name() == "volatility"
