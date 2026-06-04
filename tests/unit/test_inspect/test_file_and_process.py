"""Tests for the on-demand inspectors.

The process inspector is exercised with ``os.getpid()`` on platforms
that expose /proc; otherwise the whole file is skipped. File and
live-layer tests use tmp files / fakes so they run everywhere.
"""
from __future__ import annotations

import os
import sys

import pytest

from deepview.inspect.file import FileInspector


class TestFileInspector:
    def test_nonexistent(self, tmp_path):
        result = FileInspector(tmp_path / "nope").to_plugin_result()
        assert any("Error" in r.values() for r in result.rows) or result.columns == ["Error"]

    def test_elf_detection(self, tmp_path):
        p = tmp_path / "bin"
        p.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = FileInspector(p).to_plugin_result()
        kind_row = next((r for r in result.rows if r.get("Key") == "kind"), None)
        assert kind_row is not None
        assert kind_row["Value"] == "elf"

    def test_script_detection(self, tmp_path):
        p = tmp_path / "script.sh"
        p.write_bytes(b"#!/bin/sh\necho hi\n")
        result = FileInspector(p).to_plugin_result()
        kind_row = next((r for r in result.rows if r.get("Key") == "kind"), None)
        assert kind_row is not None
        assert kind_row["Value"] == "script"


@pytest.mark.skipif(sys.platform != "linux", reason="requires /proc")
class TestProcessInspector:
    def test_self(self):
        from deepview.inspect.process import ProcessInspector

        snap = ProcessInspector(os.getpid()).capture()
        assert snap.pid == os.getpid()
        assert snap.status["Name"]
        assert snap.cmdline
        assert len(snap.maps) > 0

    def test_plugin_result_shape(self):
        from deepview.inspect.process import ProcessInspector

        result = ProcessInspector(os.getpid()).to_plugin_result()
        assert result.columns == ["Key", "Value"]
        keys = {r["Key"] for r in result.rows}
        assert {"Exe", "Cmdline", "Maps", "Fds"}.issubset(keys)


@pytest.mark.skipif(sys.platform != "linux", reason="requires /proc")
class TestLiveProcessLayer:
    def test_regions_cover_self(self):
        from deepview.inspect.live_layer import LiveProcessLayer

        layer = LiveProcessLayer(os.getpid())
        regions = layer.regions
        assert regions
        assert layer.minimum_address <= layer.maximum_address
        layer.close()

    def test_find_region_and_is_valid(self):
        from deepview.inspect.live_layer import LiveProcessLayer

        layer = LiveProcessLayer(os.getpid())
        try:
            region = layer.regions[0]
            # A mapped address resolves to its region; is_valid agrees.
            assert layer._find_region(region.start) is region
            assert layer.is_valid(region.start, 1) is True
            # An almost-certainly-unmapped low address resolves to nothing.
            assert layer._find_region(0x1) is None
            assert layer.is_valid(0x1, 1) is False
        finally:
            layer.close()

    def test_read_padding_and_unmapped(self):
        from deepview.core.exceptions import LayerError
        from deepview.inspect.live_layer import LiveProcessLayer

        layer = LiveProcessLayer(os.getpid())
        try:
            region = layer.regions[0]
            # Mapped read with pad always yields the requested length (the
            # kernel may still refuse the actual bytes, hence pad).
            assert len(layer.read(region.start, 16, pad=True)) == 16
            # Unmapped read pads to zeros, or raises without pad.
            assert layer.read(0x1, 16, pad=True) == b"\x00" * 16
            with pytest.raises(LayerError):
                layer.read(0x1, 16)
        finally:
            layer.close()
