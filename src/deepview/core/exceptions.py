"""Deep View exception hierarchy."""


class DeepViewError(Exception):
    """Base exception for all Deep View errors."""


# -- Configuration -----------------------------------------------------------

class ConfigError(DeepViewError):
    """Invalid or missing configuration."""


# -- Plugin system -----------------------------------------------------------

class PluginError(DeepViewError):
    """Base exception for plugin-related errors."""


class PluginNotFoundError(PluginError):
    """Requested plugin could not be found."""


class PluginLoadError(PluginError):
    """Plugin failed to load."""


# -- Acquisition -------------------------------------------------------------

class AcquisitionError(DeepViewError):
    """Base exception for memory-acquisition errors."""


class UnsupportedPlatformError(AcquisitionError):
    """Operation not supported on the current platform."""


class InsufficientPrivilegesError(AcquisitionError):
    """Insufficient privileges for the requested operation."""


class ToolNotFoundError(AcquisitionError):
    """Required external tool is not installed or not on PATH."""


# -- Analysis ----------------------------------------------------------------

class AnalysisError(DeepViewError):
    """Base exception for analysis errors."""


class SymbolError(AnalysisError):
    """Symbol resolution failure."""


class LayerError(AnalysisError):
    """Memory layer error."""


class FormatError(AnalysisError):
    """Unsupported or invalid dump format."""


# -- Monitoring --------------------------------------------------------------

class MonitorError(DeepViewError):
    """Base exception for live-monitoring errors."""


class BackendNotAvailableError(MonitorError):
    """Monitoring backend (eBPF, ETW, etc.) is not available."""


class ProbeAttachError(MonitorError):
    """Failed to attach a monitoring probe."""


class FilterCompileError(MonitorError):
    """Event filter expression could not be compiled."""


# -- Instrumentation ---------------------------------------------------------

class InstrumentationError(DeepViewError):
    """Base exception for instrumentation errors."""


class AttachError(InstrumentationError):
    """Failed to attach to the target process."""


class ScriptError(InstrumentationError):
    """Instrumentation script error."""


class HookError(InstrumentationError):
    """Failed to install or remove a hook."""


# -- Reassembly / Patching --------------------------------------------------

class ReassemblyError(DeepViewError):
    """Base exception for binary reassembly errors."""


class DisassemblyError(ReassemblyError):
    """Disassembly failure."""


class RelocationError(ReassemblyError):
    """Relocation processing error."""


class PatchError(ReassemblyError):
    """Binary patching error."""


# -- Virtualisation ----------------------------------------------------------

class VMError(DeepViewError):
    """Base exception for VM introspection errors."""


class VMConnectionError(VMError):
    """Failed to connect to the hypervisor or VM."""


class SnapshotError(VMError):
    """Snapshot creation or restoration error."""


# -- Scanning ----------------------------------------------------------------

class ScanError(DeepViewError):
    """Base exception for scanning errors."""


class RuleCompileError(ScanError):
    """YARA / signature rule failed to compile."""


# -- Reporting ---------------------------------------------------------------

class ReportError(DeepViewError):
    """Report generation error."""


# -- Memory translation ------------------------------------------------------

class TranslationError(AnalysisError):
    """Virtual-to-physical address translation failure."""


class HeapParseError(AnalysisError):
    """Heap structure parsing failure."""


# -- Hardware ----------------------------------------------------------------

class HardwareError(DeepViewError):
    """Base exception for hardware-based forensic operations."""


# -- Baseline ----------------------------------------------------------------

class BaselineError(DeepViewError):
    """Baseline profiling or comparison failure."""


# -- Disassembly / Reverse Engineering --------------------------------------

class ReverseEngineeringError(DeepViewError):
    """Base exception for disassembly/reverse-engineering errors."""


class EngineNotAvailableError(ReverseEngineeringError):
    """Disassembly engine is not installed or not found."""


class DecompilationError(ReverseEngineeringError):
    """Decompilation failure."""


class AnalysisTimeoutError(ReverseEngineeringError):
    """Headless analysis exceeded time limit."""


class ProjectError(ReverseEngineeringError):
    """Ghidra/Hopper project creation or loading failure."""
