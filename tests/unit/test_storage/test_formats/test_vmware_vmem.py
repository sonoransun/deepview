"""Tests for the VMware ``.vmem`` flat-passthrough layer."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.storage.formats.vmware_vmem import VMwareVMEMLayer


class TestVMwareVMEMFlat:
    def test_round_trip(self, tmp_path: Path) -> None:
        data = bytes(range(256)) * 4  # 1 KiB
        vmem = tmp_path / "guest.vmem"
        vmem.write_bytes(data)
        with VMwareVMEMLayer(vmem) as layer:
            assert layer.read(0, len(data)) == data
            assert layer.read(128, 64) == data[128:192]
            assert layer.minimum_address == 0
            assert layer.maximum_address == len(data) - 1

    def test_pad_and_no_pad(self, tmp_path: Path) -> None:
        vmem = tmp_path / "pad.vmem"
        vmem.write_bytes(b"\x42" * 64)
        with VMwareVMEMLayer(vmem) as layer:
            assert layer.read(60, 8) == b"\x42" * 4
            assert layer.read(60, 8, pad=True) == b"\x42" * 4 + b"\x00" * 4
            assert layer.read(1000, 8) == b""
            assert layer.read(1000, 8, pad=True) == b"\x00" * 8

    def test_is_valid(self, tmp_path: Path) -> None:
        vmem = tmp_path / "bounds.vmem"
        vmem.write_bytes(b"\x00" * 32)
        with VMwareVMEMLayer(vmem) as layer:
            assert layer.is_valid(0, 32)
            assert not layer.is_valid(0, 33)
            assert not layer.is_valid(-1, 1)

    def test_write_raises(self, tmp_path: Path) -> None:
        vmem = tmp_path / "ro.vmem"
        vmem.write_bytes(b"\x00" * 4)
        with VMwareVMEMLayer(vmem) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")

    def test_metadata_uses_custom_name(self, tmp_path: Path) -> None:
        vmem = tmp_path / "m.vmem"
        vmem.write_bytes(b"\x00" * 16)
        with VMwareVMEMLayer(vmem, name="guest-mem") as layer:
            assert layer.metadata.name == "guest-mem"

    def test_not_sparse_without_sidecar(self, tmp_path: Path) -> None:
        vmem = tmp_path / "plain.vmem"
        vmem.write_bytes(b"\x00" * 16)
        with VMwareVMEMLayer(vmem) as layer:
            assert layer.is_sparse is False
            assert layer.regions == []
