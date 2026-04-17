from __future__ import annotations
import uuid
from typing import TYPE_CHECKING

from deepview.core.config import DeepViewConfig
from deepview.core.events import EventBus
from deepview.core.platform import PlatformInfo

if TYPE_CHECKING:
    from deepview.offload.engine import OffloadEngine
    from deepview.plugins.registry import PluginRegistry
    from deepview.storage.containers.unlock import UnlockOrchestrator
    from deepview.storage.manager import StorageManager


class LayerRegistry:
    """Registry for memory/data layers."""

    def __init__(self):
        self._layers: dict[str, object] = {}

    def register(self, name: str, layer: object) -> None:
        self._layers[name] = layer

    def get(self, name: str) -> object:
        if name not in self._layers:
            from deepview.core.exceptions import LayerError
            raise LayerError(f"Layer not found: {name}")
        return self._layers[name]

    def list_layers(self) -> list[str]:
        return list(self._layers.keys())

    def has(self, name: str) -> bool:
        return name in self._layers


class ArtifactStore:
    """Collected forensic artifacts during a session."""

    def __init__(self):
        self._artifacts: dict[str, list[dict]] = {}

    def add(self, category: str, artifact: dict) -> None:
        self._artifacts.setdefault(category, []).append(artifact)

    def get(self, category: str) -> list[dict]:
        return self._artifacts.get(category, [])

    def categories(self) -> list[str]:
        return list(self._artifacts.keys())

    def all_artifacts(self) -> dict[str, list[dict]]:
        return dict(self._artifacts)


class AnalysisContext:
    """Central state container for an analysis session."""

    def __init__(
        self,
        config: DeepViewConfig | None = None,
        session_id: str | None = None,
    ):
        self.config = config or DeepViewConfig()
        self.session_id = session_id or uuid.uuid4().hex
        self.layers = LayerRegistry()
        self.events = EventBus()
        self.platform = PlatformInfo.detect()
        self.artifacts = ArtifactStore()
        self._plugin_registry: PluginRegistry | None = None
        self._offload_engine: OffloadEngine | None = None
        self._storage_manager: StorageManager | None = None
        self._unlock_orchestrator: UnlockOrchestrator | None = None

    @property
    def plugins(self) -> PluginRegistry:
        if self._plugin_registry is None:
            from deepview.plugins.registry import PluginRegistry
            self._plugin_registry = PluginRegistry(self)
        return self._plugin_registry

    @property
    def offload(self) -> OffloadEngine:
        if self._offload_engine is None:
            from deepview.offload.engine import OffloadEngine
            self._offload_engine = OffloadEngine(self)
        return self._offload_engine

    @property
    def storage(self) -> StorageManager:
        if self._storage_manager is None:
            from deepview.storage.manager import StorageManager
            self._storage_manager = StorageManager(self)
        return self._storage_manager

    @property
    def unlocker(self) -> UnlockOrchestrator:
        if self._unlock_orchestrator is None:
            from deepview.storage.containers.unlock import UnlockOrchestrator
            self._unlock_orchestrator = UnlockOrchestrator(self)
        return self._unlock_orchestrator

    @classmethod
    def from_config(cls, config_path=None) -> AnalysisContext:
        config = DeepViewConfig.load(config_path)
        return cls(config=config)

    @classmethod
    def for_testing(cls) -> AnalysisContext:
        """Create a minimal context for unit tests."""
        return cls(config=DeepViewConfig())
