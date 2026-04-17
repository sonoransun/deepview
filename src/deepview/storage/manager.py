from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.interfaces.ecc import ECCDecoder
    from deepview.interfaces.filesystem import Filesystem
    from deepview.interfaces.ftl import FTLTranslator
    from deepview.storage.geometry import NANDGeometry

_logger = logging.getLogger(__name__)


class StorageError(RuntimeError):
    """Raised by the storage subsystem for adapter / probe failures."""


class StorageManager:
    """Central wiring for filesystem, FTL, and ECC adapters.

    Mirrors :class:`deepview.memory.manager.MemoryManager` style: detect what's
    available at construction, dispatch by name on demand, lazy-import every
    optional backing library inside the per-adapter modules.

    Registration and probe failures are never fatal — they are logged at
    ``WARNING`` level (registration) or ``INFO`` level (probe) so the
    ``deepview doctor`` command can surface missing optional deps instead of
    silently dropping adapters.
    """

    def __init__(self, context: AnalysisContext) -> None:
        self._context = context
        self._fs_adapters: dict[str, type[Filesystem]] = {}
        self._ftl_translators: dict[str, type[FTLTranslator]] = {}
        self._ecc_decoders: dict[str, type[ECCDecoder]] = {}
        try:
            from deepview.storage.filesystems.registry import register_all

            register_all(self)
        except (ImportError, RuntimeError, AttributeError) as exc:
            _logger.warning(
                "storage filesystem registry unavailable: %s", exc
            )

    # ------------------------------------------------------------------
    # Registration (called by adapters at import time)
    # ------------------------------------------------------------------

    def register_filesystem(self, name: str, cls: type[Filesystem]) -> None:
        self._fs_adapters[name] = cls

    def register_ftl(self, name: str, cls: type[FTLTranslator]) -> None:
        self._ftl_translators[name] = cls

    def register_ecc(self, name: str, cls: type[ECCDecoder]) -> None:
        self._ecc_decoders[name] = cls

    # ------------------------------------------------------------------
    # Filesystem dispatch
    # ------------------------------------------------------------------

    def open_filesystem(
        self,
        layer: DataLayer,
        fs_type: str | None = None,
        offset: int = 0,
    ) -> Filesystem:
        """Open *layer* as a filesystem; auto-probe when *fs_type* is None."""
        if fs_type is not None:
            cls = self._fs_adapters.get(fs_type)
            if cls is None:
                raise StorageError(f"Unknown filesystem adapter: {fs_type}")
            return cls(layer, offset)
        for name, cls in self._fs_adapters.items():
            try:
                if cls.probe(layer, offset):
                    return cls(layer, offset)
            except (ImportError, RuntimeError, ValueError, OSError) as exc:
                _logger.info("filesystem probe %s skipped: %s", name, exc)
                continue
        raise StorageError("No filesystem adapter recognised the layer")

    # ------------------------------------------------------------------
    # NAND wrapping (raw -> ECC -> linearized)
    # ------------------------------------------------------------------

    def wrap_nand(
        self,
        layer: DataLayer,
        geometry: NANDGeometry,
        *,
        ecc: ECCDecoder | None = None,
        ftl: FTLTranslator | None = None,
    ) -> DataLayer:
        """Compose RawNAND -> (optional ECC) -> (optional FTL) and return the top layer."""
        result = layer
        if ecc is not None:
            from deepview.storage.ecc.base import ECCDataLayer

            result = ECCDataLayer(result, ecc, geometry)
        if ftl is not None:
            from deepview.storage.ftl.linearized import LinearizedFlashLayer

            result = LinearizedFlashLayer(result, ftl, geometry)
        return result

    # ------------------------------------------------------------------
    # Probing
    # ------------------------------------------------------------------

    def probe(self, layer: DataLayer) -> list[str]:
        """Return names of adapters whose probe succeeded against *layer*."""
        hits: list[str] = []
        for name, cls in self._fs_adapters.items():
            try:
                if cls.probe(layer, 0):
                    hits.append(f"filesystem:{name}")
            except (ImportError, RuntimeError, ValueError, OSError) as exc:
                _logger.info("filesystem probe %s skipped: %s", name, exc)
                continue
        return hits

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def filesystems(self) -> list[str]:
        return list(self._fs_adapters)

    def ftl_translators(self) -> list[str]:
        return list(self._ftl_translators)

    def ecc_decoders(self) -> list[str]:
        return list(self._ecc_decoders)
