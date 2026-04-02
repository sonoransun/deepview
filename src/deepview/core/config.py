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

    @classmethod
    def load(cls, config_path: Path | None = None) -> DeepViewConfig:
        """Load configuration, merging defaults with config file if present."""
        if config_path and config_path.exists():
            import tomllib
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
            return cls(**data)

        default_path = Path(user_config_dir(_APP_NAME)) / "config.toml"
        if default_path.exists():
            import tomllib
            with open(default_path, "rb") as f:
                data = tomllib.load(f)
            return cls(**data)

        return cls()
