"""Tests for the exception hierarchy."""
import pytest

from deepview.core.exceptions import (
    AcquisitionError,
    AnalysisError,
    AttachError,
    BackendNotAvailableError,
    BaselineError,
    ConfigError,
    DeepViewError,
    DisassemblyError,
    FilterCompileError,
    FormatError,
    HardwareError,
    HeapParseError,
    HookError,
    InstrumentationError,
    InsufficientPrivilegesError,
    LayerError,
    MonitorError,
    PatchError,
    PluginError,
    PluginLoadError,
    PluginNotFoundError,
    ProbeAttachError,
    ReassemblyError,
    RelocationError,
    ReportError,
    RuleCompileError,
    ScanError,
    ScriptError,
    SnapshotError,
    SymbolError,
    ToolNotFoundError,
    TranslationError,
    UnsupportedPlatformError,
    VMConnectionError,
    VMError,
)

ALL_EXCEPTIONS = [
    ConfigError,
    PluginError,
    PluginNotFoundError,
    PluginLoadError,
    AcquisitionError,
    UnsupportedPlatformError,
    InsufficientPrivilegesError,
    ToolNotFoundError,
    AnalysisError,
    SymbolError,
    LayerError,
    FormatError,
    TranslationError,
    HeapParseError,
    MonitorError,
    BackendNotAvailableError,
    ProbeAttachError,
    FilterCompileError,
    InstrumentationError,
    AttachError,
    ScriptError,
    HookError,
    ReassemblyError,
    DisassemblyError,
    RelocationError,
    PatchError,
    VMError,
    VMConnectionError,
    SnapshotError,
    ScanError,
    RuleCompileError,
    ReportError,
    HardwareError,
    BaselineError,
]

# Maps each child exception to its expected direct parent
HIERARCHY = {
    ConfigError: DeepViewError,
    PluginError: DeepViewError,
    PluginNotFoundError: PluginError,
    PluginLoadError: PluginError,
    AcquisitionError: DeepViewError,
    UnsupportedPlatformError: AcquisitionError,
    InsufficientPrivilegesError: AcquisitionError,
    ToolNotFoundError: AcquisitionError,
    AnalysisError: DeepViewError,
    SymbolError: AnalysisError,
    LayerError: AnalysisError,
    FormatError: AnalysisError,
    TranslationError: AnalysisError,
    HeapParseError: AnalysisError,
    MonitorError: DeepViewError,
    BackendNotAvailableError: MonitorError,
    ProbeAttachError: MonitorError,
    FilterCompileError: MonitorError,
    InstrumentationError: DeepViewError,
    AttachError: InstrumentationError,
    ScriptError: InstrumentationError,
    HookError: InstrumentationError,
    ReassemblyError: DeepViewError,
    DisassemblyError: ReassemblyError,
    RelocationError: ReassemblyError,
    PatchError: ReassemblyError,
    VMError: DeepViewError,
    VMConnectionError: VMError,
    SnapshotError: VMError,
    ScanError: DeepViewError,
    RuleCompileError: ScanError,
    ReportError: DeepViewError,
    HardwareError: DeepViewError,
    BaselineError: DeepViewError,
}


class TestExceptionInheritance:
    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
    def test_all_exceptions_inherit_from_deepview_error(self, exc_cls):
        instance = exc_cls("test error")
        assert isinstance(instance, DeepViewError)

    @pytest.mark.parametrize("child,parent", HIERARCHY.items(), ids=lambda x: x.__name__)
    def test_exception_hierarchy(self, child, parent):
        instance = child("hierarchy test")
        assert isinstance(instance, parent)
        assert issubclass(child, parent)


class TestExceptionMessages:
    def test_exception_message_propagation(self):
        msg = "something went wrong in analysis"
        err = AnalysisError(msg)
        assert str(err) == msg

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
    def test_exception_can_be_caught_by_base(self, exc_cls):
        with pytest.raises(DeepViewError):
            raise exc_cls("catch me")
