"""Tests for core type definitions."""
from deepview.core.types import (
    Platform, PrivilegeLevel, DumpFormat, ProbeType,
    EventCategory, EventSeverity, PluginCategory,
    ProcessContext, EventSource, LayerMetadata,
    AcquisitionResult, PluginMetadata, ScanResult, ModuleInfo,
)

class TestEnums:
    def test_platform_values(self):
        assert Platform.LINUX.value == "linux"
        assert Platform.MACOS.value == "darwin"
        assert Platform.WINDOWS.value == "windows"

    def test_privilege_level_values(self):
        assert PrivilegeLevel.USER.value == "user"
        assert PrivilegeLevel.ROOT.value == "root"

    def test_dump_format_values(self):
        assert DumpFormat.RAW.value == "raw"
        assert DumpFormat.LIME.value == "lime"

    def test_event_category_values(self):
        assert EventCategory.PROCESS.value == "process"
        assert EventCategory.NETWORK.value == "network"

class TestModels:
    def test_process_context_defaults(self):
        pc = ProcessContext(pid=1, tid=1, ppid=0, uid=0, gid=0, comm="init")
        assert pc.pid == 1
        assert pc.exe_path == ""
        assert pc.cgroup == ""

    def test_plugin_metadata_defaults(self):
        pm = PluginMetadata(name="test")
        assert pm.version == "0.1.0"
        assert len(pm.platforms) == 3

    def test_scan_result(self):
        sr = ScanResult(offset=0x1000, length=64, rule_name="test_rule")
        assert sr.offset == 0x1000
        assert sr.data == b""

    def test_module_info(self):
        mi = ModuleInfo(name="libc.so.6", base_address=0x7fff0000, size=0x200000)
        assert mi.path == ""

    def test_acquisition_result(self):
        ar = AcquisitionResult(success=True, format=DumpFormat.RAW)
        assert ar.size_bytes == 0
        assert ar.hash_sha256 == ""
