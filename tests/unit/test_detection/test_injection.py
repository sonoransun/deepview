"""Tests for deepview.detection.injection module."""
from __future__ import annotations

import pytest

from deepview.core.types import EventSeverity
from deepview.detection.anti_forensics import Detection
from deepview.detection.injection import InjectionDetector


class TestDetectHollowProcesses:
    """Tests for InjectionDetector.detect_hollow_processes."""

    def test_detect_hollow_process(self):
        """Mismatched bases -> detection with technique T1055.012."""
        detector = InjectionDetector()
        processes = [
            {
                "pid": 1234,
                "name": "svchost.exe",
                "peb_image_base": 0x00400000,
                "actual_image_base": 0x10000000,
            },
        ]
        detections = detector.detect_hollow_processes(processes)
        assert len(detections) == 1
        assert detections[0].name == "PROCESS_HOLLOWING"
        assert detections[0].severity == EventSeverity.CRITICAL
        assert detections[0].technique == "T1055.012"
        assert detections[0].pid == 1234
        assert detections[0].process_name == "svchost.exe"

    def test_detect_no_hollow_when_matching(self):
        """Matching bases -> no detection."""
        detector = InjectionDetector()
        processes = [
            {
                "pid": 1234,
                "name": "svchost.exe",
                "peb_image_base": 0x00400000,
                "actual_image_base": 0x00400000,
            },
        ]
        detections = detector.detect_hollow_processes(processes)
        assert detections == []


class TestDetectInjectedCode:
    """Tests for InjectionDetector.detect_injected_code."""

    def test_detect_injected_code_rwx(self):
        """EXECUTE+WRITE, private, no file -> detection."""
        detector = InjectionDetector()
        vad_entries = [
            {
                "pid": 500,
                "process": "malware.exe",
                "start": 0x10000,
                "end": 0x20000,
                "protection": "PAGE_EXECUTE_READWRITE",
                "private": True,
                "file_object": None,
            },
        ]
        detections = detector.detect_injected_code(vad_entries)
        assert len(detections) == 1
        assert detections[0].name == "INJECTED_CODE"
        assert detections[0].severity == EventSeverity.WARNING
        assert detections[0].technique == "T1055"

    def test_detect_injected_code_normal(self):
        """READ only, has file -> no detection."""
        detector = InjectionDetector()
        vad_entries = [
            {
                "pid": 500,
                "process": "notepad.exe",
                "start": 0x10000,
                "end": 0x20000,
                "protection": "PAGE_READONLY",
                "private": False,
                "file_object": "C:\\Windows\\notepad.exe",
            },
        ]
        detections = detector.detect_injected_code(vad_entries)
        assert detections == []


class TestDetectSuspiciousThreads:
    """Tests for InjectionDetector.detect_suspicious_threads."""

    def test_detect_suspicious_thread(self):
        """in_known_module=False -> detection."""
        detector = InjectionDetector()
        threads = [
            {
                "tid": 42,
                "pid": 1234,
                "start_address": 0xDEADBEEF,
                "in_known_module": False,
            },
        ]
        detections = detector.detect_suspicious_threads(threads)
        assert len(detections) == 1
        assert detections[0].name == "SUSPICIOUS_THREAD"
        assert detections[0].severity == EventSeverity.WARNING
        assert detections[0].technique == "T1055.003"
        assert detections[0].pid == 1234

    def test_detect_normal_thread(self):
        """in_known_module=True -> no detection."""
        detector = InjectionDetector()
        threads = [
            {
                "tid": 42,
                "pid": 1234,
                "start_address": 0x7FF600000000,
                "in_known_module": True,
            },
        ]
        detections = detector.detect_suspicious_threads(threads)
        assert detections == []


class TestDetectPEBMasquerade:
    """Tests for InjectionDetector.detect_peb_masquerade."""

    def test_detect_peb_masquerade(self):
        """Mismatched paths -> detection."""
        detector = InjectionDetector()
        processes = [
            {
                "pid": 789,
                "name": "svchost.exe",
                "peb_image_path": "C:\\Windows\\System32\\svchost.exe",
                "actual_image_path": "C:\\Temp\\malware.exe",
            },
        ]
        detections = detector.detect_peb_masquerade(processes)
        assert len(detections) == 1
        assert detections[0].name == "PEB_MASQUERADE"
        assert detections[0].severity == EventSeverity.CRITICAL
        assert detections[0].technique == "T1036.005"
        assert detections[0].pid == 789


class TestAllDetectionsProperty:
    """Tests for InjectionDetector.all_detections accumulation."""

    def test_all_detections_property(self):
        """Verify accumulation across multiple detect methods."""
        detector = InjectionDetector()

        # Hollow process
        detector.detect_hollow_processes([
            {
                "pid": 1,
                "name": "a.exe",
                "peb_image_base": 0x1000,
                "actual_image_base": 0x2000,
            },
        ])

        # Injected code
        detector.detect_injected_code([
            {
                "pid": 2,
                "process": "b.exe",
                "start": 0x3000,
                "end": 0x4000,
                "protection": "PAGE_EXECUTE_READWRITE",
                "private": True,
                "file_object": None,
            },
        ])

        # Suspicious thread
        detector.detect_suspicious_threads([
            {
                "tid": 10,
                "pid": 3,
                "start_address": 0x5000,
                "in_known_module": False,
            },
        ])

        # PEB masquerade
        detector.detect_peb_masquerade([
            {
                "pid": 4,
                "name": "c.exe",
                "peb_image_path": "C:\\real.exe",
                "actual_image_path": "C:\\fake.exe",
            },
        ])

        all_dets = detector.all_detections
        assert len(all_dets) == 4
        names = {d.name for d in all_dets}
        assert "PROCESS_HOLLOWING" in names
        assert "INJECTED_CODE" in names
        assert "SUSPICIOUS_THREAD" in names
        assert "PEB_MASQUERADE" in names
