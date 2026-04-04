"""Tests for deepview.detection.anti_forensics module."""
from __future__ import annotations

import pytest

from deepview.core.types import EventSeverity
from deepview.detection.anti_forensics import AntiForensicsDetector, Detection


class TestDetectDKOM:
    """Tests for AntiForensicsDetector.detect_dkom."""

    def test_detect_dkom_no_hidden_processes(self):
        """All PIDs present in all sources -> no detections."""
        detector = AntiForensicsDetector()
        process_lists = {
            "PsActiveProcessHead": [
                {"pid": 4, "name": "System"},
                {"pid": 100, "name": "svchost.exe"},
            ],
            "PspCidTable": [
                {"pid": 4, "name": "System"},
                {"pid": 100, "name": "svchost.exe"},
            ],
        }
        detections = detector.detect_dkom(process_lists)
        assert detections == []

    def test_detect_dkom_hidden_process(self):
        """PID in source A but not source B -> detection."""
        detector = AntiForensicsDetector()
        process_lists = {
            "PsActiveProcessHead": [
                {"pid": 4, "name": "System"},
            ],
            "PspCidTable": [
                {"pid": 4, "name": "System"},
                {"pid": 666, "name": "rootkit.exe"},
            ],
        }
        detections = detector.detect_dkom(process_lists)
        assert len(detections) == 1
        assert detections[0].name == "DKOM_HIDDEN_PROCESS"
        assert detections[0].severity == EventSeverity.CRITICAL
        assert detections[0].pid == 666
        assert detections[0].technique == "T1014"
        assert "PspCidTable" in detections[0].evidence["present_in"]
        assert "PsActiveProcessHead" in detections[0].evidence["missing_from"]

    def test_detect_dkom_single_source(self):
        """Only one source -> no detections (needs 2+)."""
        detector = AntiForensicsDetector()
        process_lists = {
            "PsActiveProcessHead": [
                {"pid": 4, "name": "System"},
                {"pid": 100, "name": "svchost.exe"},
            ],
        }
        detections = detector.detect_dkom(process_lists)
        assert detections == []


class TestDetectSSDTHooks:
    """Tests for AntiForensicsDetector.detect_ssdt_hooks."""

    def test_detect_ssdt_hook(self):
        """Entry with actual_module != expected_module -> detection."""
        detector = AntiForensicsDetector()
        entries = [
            {
                "index": 0,
                "name": "NtCreateFile",
                "address": 0xFFFFF80012345678,
                "expected_module": "ntoskrnl",
                "actual_module": "evil_driver",
            },
        ]
        detections = detector.detect_ssdt_hooks(entries)
        assert len(detections) == 1
        assert detections[0].name == "SSDT_HOOK"
        assert detections[0].severity == EventSeverity.CRITICAL
        assert detections[0].technique == "T1574.013"
        assert "evil_driver" in detections[0].description

    def test_detect_ssdt_no_hooks(self):
        """Matching modules -> no detections."""
        detector = AntiForensicsDetector()
        entries = [
            {
                "index": 0,
                "name": "NtCreateFile",
                "address": 0xFFFFF80012345678,
                "expected_module": "ntoskrnl",
                "actual_module": "ntoskrnl",
            },
        ]
        detections = detector.detect_ssdt_hooks(entries)
        assert detections == []


class TestDetectInlineHooks:
    """Tests for AntiForensicsDetector.detect_inline_hooks."""

    def test_detect_inline_hook_jmp(self):
        """Prologue starting with 0xE9 (JMP rel32) -> detection."""
        detector = AntiForensicsDetector()
        functions = [
            {
                "name": "NtQuerySystemInformation",
                "address": 0xFFFFF80011111111,
                "prologue_bytes": b"\xe9\x00\x10\x00\x00" + b"\x90" * 11,
            },
        ]
        detections = detector.detect_inline_hooks(functions)
        assert len(detections) == 1
        assert detections[0].name == "INLINE_HOOK"
        assert detections[0].severity == EventSeverity.WARNING
        assert detections[0].technique == "T1574"

    def test_detect_inline_hook_clean(self):
        """Prologue starting with 0x55 (push rbp) -> no detection."""
        detector = AntiForensicsDetector()
        functions = [
            {
                "name": "NtQuerySystemInformation",
                "address": 0xFFFFF80011111111,
                "prologue_bytes": b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
            },
        ]
        detections = detector.detect_inline_hooks(functions)
        assert detections == []


class TestDetectionAccumulation:
    """Tests for all_detections property and clear method."""

    def test_all_detections_accumulate(self):
        """Run multiple detect methods, verify all_detections has all."""
        detector = AntiForensicsDetector()

        # Trigger DKOM detection
        detector.detect_dkom({
            "source_a": [{"pid": 1, "name": "a"}],
            "source_b": [{"pid": 1, "name": "a"}, {"pid": 999, "name": "hidden"}],
        })

        # Trigger SSDT hook detection
        detector.detect_ssdt_hooks([
            {
                "index": 5,
                "name": "NtReadFile",
                "address": 0x1000,
                "expected_module": "ntoskrnl",
                "actual_module": "rootkit",
            },
        ])

        # Trigger inline hook detection
        detector.detect_inline_hooks([
            {
                "name": "func",
                "address": 0x2000,
                "prologue_bytes": b"\xe9\x00\x00\x00\x00",
            },
        ])

        all_dets = detector.all_detections
        assert len(all_dets) == 3
        names = {d.name for d in all_dets}
        assert "DKOM_HIDDEN_PROCESS" in names
        assert "SSDT_HOOK" in names
        assert "INLINE_HOOK" in names

    def test_clear_resets(self):
        """Verify clear() empties detections."""
        detector = AntiForensicsDetector()

        detector.detect_ssdt_hooks([
            {
                "index": 0,
                "name": "NtCreateFile",
                "address": 0x1000,
                "expected_module": "ntoskrnl",
                "actual_module": "bad_driver",
            },
        ])
        assert len(detector.all_detections) == 1

        detector.clear()
        assert len(detector.all_detections) == 0
