"""Tests for the Hyper-V ``.vmrs`` / ``.bin`` layer."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepview.storage.formats.hyperv_vmrs import HyperVVMRSLayer


def _build_pair(base: Path, bin_bytes: bytes) -> tuple[Path, Path]:
    vmrs = base.with_suffix(".vmrs")
    binf = base.with_suffix(".bin")
    # Stub VMRS with a recognised magic so init doesn't reject it.
    vmrs.write_bytes(b"VMRS" + b"\x00" * 124)
    binf.write_bytes(bin_bytes)
    return vmrs, binf


class TestHyperVVMRS:
    def test_flat_read(self, tmp_path: Path) -> None:
        payload = bytes(range(256))
        vmrs, binf = _build_pair(tmp_path / "guest", payload)
        with HyperVVMRSLayer(vmrs) as layer:
            assert layer.bin_path == binf
            assert layer.vmrs_path == vmrs
            assert layer.read(0, len(payload)) == payload
            assert layer.read(64, 32) == payload[64:96]
            assert layer.minimum_address == 0
            assert layer.maximum_address == len(payload) - 1

    def test_pad_vs_nopad(self, tmp_path: Path) -> None:
        vmrs, _binf = _build_pair(tmp_path / "g", b"\xAA" * 16)
        with HyperVVMRSLayer(vmrs) as layer:
            assert layer.read(12, 8) == b"\xAA" * 4
            assert layer.read(12, 8, pad=True) == b"\xAA" * 4 + b"\x00" * 4
            assert layer.read(100, 8) == b""
            assert layer.read(100, 8, pad=True) == b"\x00" * 8

    def test_is_valid(self, tmp_path: Path) -> None:
        vmrs, _binf = _build_pair(tmp_path / "g", b"\x00" * 32)
        with HyperVVMRSLayer(vmrs) as layer:
            assert layer.is_valid(0, 32)
            assert not layer.is_valid(0, 33)
            assert not layer.is_valid(-1, 1)

    def test_write_raises(self, tmp_path: Path) -> None:
        vmrs, _binf = _build_pair(tmp_path / "g", b"\x00" * 8)
        with HyperVVMRSLayer(vmrs) as layer:
            with pytest.raises(NotImplementedError):
                layer.write(0, b"x")

    def test_missing_bin_raises(self, tmp_path: Path) -> None:
        vmrs = tmp_path / "only.vmrs"
        vmrs.write_bytes(b"VMRS" + b"\x00" * 124)
        with pytest.raises(FileNotFoundError):
            HyperVVMRSLayer(vmrs)

    def test_metadata_flat_fallback(self, tmp_path: Path) -> None:
        vmrs, _binf = _build_pair(tmp_path / "g", b"\x11" * 8)
        with HyperVVMRSLayer(vmrs, name="hv") as layer:
            # With an unparseable GPADL header, we expose "(flat)" tagging.
            assert "(flat)" in layer.metadata.name
            assert layer.parsed_gpadl is False
