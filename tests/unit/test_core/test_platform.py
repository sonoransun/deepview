"""Tests for platform detection and capabilities."""
import tempfile
from pathlib import Path

from deepview.core.platform import (
    PlatformInfo,
    _check_file_readable,
    check_privileges,
    detect_platform,
)
from deepview.core.types import Platform, PrivilegeLevel


class TestDetectPlatform:
    def test_detect_platform_returns_valid_enum(self):
        result = detect_platform()
        assert isinstance(result, Platform)
        assert result in (Platform.LINUX, Platform.MACOS, Platform.WINDOWS)


class TestPlatformInfo:
    def test_platform_info_detect(self):
        info = PlatformInfo.detect()
        assert isinstance(info, PlatformInfo)
        assert isinstance(info.os, Platform)
        assert isinstance(info.arch, str)
        assert len(info.arch) > 0
        assert isinstance(info.kernel_version, str)
        assert len(info.kernel_version) > 0
        assert isinstance(info.capabilities, set)


class TestCheckPrivileges:
    def test_check_privileges_returns_privilege_level(self):
        result = check_privileges()
        assert isinstance(result, PrivilegeLevel)
        assert result in (
            PrivilegeLevel.USER,
            PrivilegeLevel.ELEVATED,
            PrivilegeLevel.ROOT,
            PrivilegeLevel.KERNEL,
        )


class TestCheckFileReadable:
    def test_check_file_readable_existing_file(self):
        with tempfile.NamedTemporaryFile() as tmp:
            assert _check_file_readable(tmp.name) is True

    def test_check_file_readable_nonexistent(self):
        assert _check_file_readable("/nonexistent/path/file.bin") is False
