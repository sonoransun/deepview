from __future__ import annotations
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings
from platformdirs import user_config_dir, user_cache_dir

_APP_NAME = "deepview"

class MemoryConfig(BaseSettings):
    default_engine: str = "volatility"
    symbol_cache_dir: Path = Path(user_cache_dir(_APP_NAME)) / "symbols"
    yara_rules_dir: Path = Path(user_config_dir(_APP_NAME)) / "rules"

class AcquisitionConfig(BaseSettings):
    default_method: str = "auto"
    compress: bool = True

class VMConfig(BaseSettings):
    default_hypervisor: str = "auto"
    libvirt_uri: str = "qemu:///system"

class TracingConfig(BaseSettings):
    default_duration: int = 30
    ring_buffer_pages: int = 64

class InstrumentationConfig(BaseSettings):
    frida_server_path: str = ""

class ReportingConfig(BaseSettings):
    default_template: str = "html"
    output_dir: Path = Path(user_config_dir(_APP_NAME)) / "reports"


class HardwareConfig(BaseSettings):
    dma_backend: str = "auto"
    pcileech_device: str = ""
    cold_boot_temperature_c: float = -50.0
    cold_boot_elapsed_s: float = 0.0


class FirmwareConfig(BaseSettings):
    spi_backend: str = "auto"
    chipsec_modules: list[str] = Field(default_factory=list)
    known_good_firmware_db: str = ""


class GPUConfig(BaseSettings):
    backend: str = "auto"
    cuda_device_id: int = 0


class SideChannelConfig(BaseSettings):
    sdr_device: str = ""
    chipwhisperer_serial: str = ""
    sample_rate_hz: int = 20_000_000


class ClassificationConfig(BaseSettings):
    enabled: bool = True
    ruleset_paths: list[str] = Field(default_factory=list)
    load_builtin: bool = True
    anomaly_window_s: float = 30.0
    auto_inspect_on_severity: str = "critical"


class ReplayConfig(BaseSettings):
    store_path: Path = Path(user_cache_dir(_APP_NAME)) / "sessions"
    circular_buffer_seconds: float = 60.0
    snapshot_interval_s: float = 5.0


class MonitorConfig(BaseSettings):
    default_ruleset: str = ""
    refresh_hz: float = 4.0
    max_rows: int = 25


class DashboardConfig(BaseSettings):
    default_layout: str = "network"
    refresh_hz: float = 4.0
    config_path: str = ""


class NetworkMangleConfig(BaseSettings):
    queue_num: int = 42
    state_dir: Path = Path(user_cache_dir(_APP_NAME)) / "mangle"
    dry_run_default: bool = False
    fail_open: bool = True
    iptables_chain: str = "OUTPUT"
    iptables_table: str = "mangle"
    iptables_binary: str = "iptables"


class DisassemblyConfig(BaseSettings):
    default_engine: str = "auto"
    ghidra_install_dir: str = ""
    ghidra_project_dir: str = ""
    ghidra_jvm_args: list[str] = Field(default_factory=lambda: ["-Xmx4g"])
    ghidra_analysis_timeout: int = 600
    hopper_cli_path: str = ""
    hopper_license_path: str = ""
    capstone_detail_mode: bool = True

class DeepViewConfig(BaseSettings):
    model_config = {"env_prefix": "DEEPVIEW_"}

    log_level: str = "info"
    output_format: str = "table"
    plugin_paths: list[str] = Field(default_factory=list)
    config_dir: Path = Path(user_config_dir(_APP_NAME))
    cache_dir: Path = Path(user_cache_dir(_APP_NAME))

    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    acquisition: AcquisitionConfig = Field(default_factory=AcquisitionConfig)
    vm: VMConfig = Field(default_factory=VMConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    instrumentation: InstrumentationConfig = Field(default_factory=InstrumentationConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    hardware: HardwareConfig = Field(default_factory=HardwareConfig)
    firmware: FirmwareConfig = Field(default_factory=FirmwareConfig)
    gpu: GPUConfig = Field(default_factory=GPUConfig)
    sidechannel: SideChannelConfig = Field(default_factory=SideChannelConfig)
    disassembly: DisassemblyConfig = Field(default_factory=DisassemblyConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    replay: ReplayConfig = Field(default_factory=ReplayConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    network_mangle: NetworkMangleConfig = Field(default_factory=NetworkMangleConfig)

    @classmethod
    def load(cls, config_path: Path | None = None) -> DeepViewConfig:
        """Load configuration, merging defaults with config file if present."""
        from deepview.core.exceptions import ConfigError

        _MAX_CONFIG_SIZE = 10 * 1024 * 1024  # 10 MB

        def _validate_config_file(path: Path) -> None:
            """Security checks before loading a config file."""
            resolved = path.resolve()
            if path.is_symlink():
                raise ConfigError(f"Config file is a symlink (rejected): {path}")
            if not resolved.is_file():
                raise ConfigError(f"Config path is not a regular file: {path}")
            try:
                size = resolved.stat().st_size
            except OSError as e:
                raise ConfigError(f"Cannot stat config file {path}: {e}") from e
            if size > _MAX_CONFIG_SIZE:
                raise ConfigError(
                    f"Config file too large ({size} bytes, max {_MAX_CONFIG_SIZE}): {path}"
                )

        def _load_toml(path: Path) -> DeepViewConfig:
            import tomllib
            _validate_config_file(path)
            try:
                with open(path, "rb") as f:
                    data = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise ConfigError(f"Invalid TOML in {path}: {e}") from e
            except OSError as e:
                raise ConfigError(f"Cannot read config file {path}: {e}") from e
            try:
                return cls(**data)
            except Exception as e:
                raise ConfigError(f"Invalid configuration in {path}: {e}") from e

        if config_path and config_path.exists():
            return _load_toml(config_path)

        default_path = Path(user_config_dir(_APP_NAME)) / "config.toml"
        if default_path.exists():
            return _load_toml(default_path)

        return cls()
