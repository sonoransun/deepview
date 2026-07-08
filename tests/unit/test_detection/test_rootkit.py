"""Tests for boot-sector (bootkit) integrity detection."""
from __future__ import annotations

from deepview.core.types import EventSeverity
from deepview.detection.rootkit import BootkitDetector


def _valid_mbr(code: bytes = b"\xEB\x3C\x90" + b"\xAA" * 100) -> bytes:
    sector = bytearray(512)
    sector[0 : len(code)] = code
    sector[0x1FE:0x200] = b"\x55\xAA"
    return bytes(sector)


class TestAnalyzeMBR:
    def test_valid_mbr_no_findings(self):
        assert BootkitDetector().analyze_mbr(_valid_mbr()) == []

    def test_bad_signature_is_critical(self):
        sector = bytearray(_valid_mbr())
        sector[0x1FE:0x200] = b"\x00\x00"
        dets = BootkitDetector().analyze_mbr(bytes(sector))
        assert any(d.severity == EventSeverity.CRITICAL for d in dets)
        assert all(d.technique == "T1542.003" for d in dets)

    def test_zeroed_bootstrap_flagged(self):
        sector = bytearray(512)
        sector[0x1FE:0x200] = b"\x55\xAA"  # valid signature, empty bootstrap
        dets = BootkitDetector().analyze_mbr(bytes(sector))
        assert any("zero" in d.description.lower() for d in dets)

    def test_short_sector(self):
        dets = BootkitDetector().analyze_mbr(b"\x00" * 100)
        assert len(dets) == 1
        assert dets[0].severity == EventSeverity.WARNING


class TestKnownGoodComparison:
    def test_bootstrap_code_deviation_is_critical(self):
        good = _valid_mbr()
        bad = bytearray(good)
        bad[0] = 0xEA  # alter bootstrap code
        dets = BootkitDetector().compare_to_known_good(bytes(bad), good)
        assert len(dets) == 1
        assert dets[0].severity == EventSeverity.CRITICAL

    def test_partition_table_difference_ignored(self):
        good = _valid_mbr()
        variant = bytearray(good)
        variant[0x1BE] = 0x80  # bootable flag in the partition table only
        assert BootkitDetector().compare_to_known_good(bytes(variant), good) == []


class TestAnalyzeImage:
    def test_reads_first_sector(self, tmp_path):
        img = tmp_path / "disk.img"
        img.write_bytes(_valid_mbr() + b"\x00" * 4096)
        assert BootkitDetector().analyze_image(img) == []

    def test_flags_tampered_image(self, tmp_path):
        img = tmp_path / "disk.img"
        img.write_bytes(bytes(512))  # all-zero: bad signature + empty bootstrap
        dets = BootkitDetector().analyze_image(img)
        assert len(dets) >= 1
