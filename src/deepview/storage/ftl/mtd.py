"""MTD passthrough: 1:1 physical-to-logical mapping with bad-block skip."""
from __future__ import annotations

from collections.abc import Iterator

from deepview.interfaces.ftl import FTLTranslator, LBAMapping
from deepview.interfaces.layer import DataLayer
from deepview.storage.ftl.badblock import BadBlockRemapTranslator
from deepview.storage.geometry import NANDGeometry


class MTDPassthroughTranslator(FTLTranslator):
    """Pure 1:1 identity translator using the bad-block-table spare markers.

    Delegates to :class:`BadBlockRemapTranslator` but identifies itself as
    ``"mtd"`` so it can be selected explicitly from configuration.
    """

    name = "mtd"

    def __init__(
        self,
        geometry: NANDGeometry,
        bad_blocks: set[int] | None = None,
    ) -> None:
        self._geometry = geometry
        self._inner = BadBlockRemapTranslator(geometry, bad_blocks=bad_blocks)

    @classmethod
    def probe(cls, layer: DataLayer, geometry: NANDGeometry) -> bool:  # type: ignore[override]
        # MTD passthrough always applies as a last-resort translator.
        return True

    def build_map(
        self,
        layer: DataLayer | None = None,
        geometry: NANDGeometry | None = None,
    ) -> Iterator[LBAMapping]:
        yield from self._inner.build_map(layer, geometry)

    def translate(self, lba: int) -> LBAMapping | None:
        return self._inner.translate(lba)

    def logical_size(self) -> int:
        return self._inner.logical_size()
