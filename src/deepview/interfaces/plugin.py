from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from deepview.core.types import Platform, PluginMetadata

# AnalysisContext imported at runtime to avoid a circular import between
# interfaces and core.context (context references PluginRegistry which
# may reference plugins that depend on these interfaces).
from deepview.core.context import AnalysisContext


# ------------------------------------------------------------------
# Supporting types
# ------------------------------------------------------------------


class RequirementType(str, enum.Enum):
    LAYER = "layer"
    CONFIG = "config"
    PLUGIN_OUTPUT = "plugin_output"
    PRIVILEGE = "privilege"


@dataclass
class Requirement:
    """A single requirement declared by a plugin."""

    name: str
    description: str
    required: bool = True
    requirement_type: RequirementType = RequirementType.CONFIG
    default: Any = None


@dataclass
class PluginResult:
    """Tabular result returned by a plugin's :meth:`run` method."""

    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ------------------------------------------------------------------
# ABC
# ------------------------------------------------------------------


class DeepViewPlugin(ABC):
    """Base class for all Deep View analysis plugins."""

    def __init__(
        self,
        context: AnalysisContext,
        config: dict | None = None,
    ) -> None:
        self.context = context
        self.config = config or {}

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @classmethod
    @abstractmethod
    def get_requirements(cls) -> list[Requirement]:
        """Declare the inputs this plugin needs before it can run."""

    @abstractmethod
    def run(self) -> PluginResult:
        """Execute the plugin and return structured results."""

    # ------------------------------------------------------------------
    # Overridable class methods with sensible defaults
    # ------------------------------------------------------------------

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Return descriptive metadata for this plugin.

        Subclasses should override this to provide accurate information.
        The default returns a bare-minimum :class:`PluginMetadata`
        derived from the class name.
        """
        return PluginMetadata(name=cls.__name__)

    @classmethod
    def supported_platforms(cls) -> list[Platform]:
        """Platforms on which this plugin is expected to work.

        Defaults to all platforms.
        """
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]
