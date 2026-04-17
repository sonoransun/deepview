"""NAND ECC/FTL decode statistics plugin.

Wraps a registered raw-NAND layer with the requested ECC decoder + FTL
translator, walks every page, and reports correction statistics:
``corrected`` / ``uncorrectable`` / ``pages_read`` / ``bad_blocks``.
"""
from __future__ import annotations

from typing import Any

from deepview.core.types import PluginCategory
from deepview.interfaces.plugin import DeepViewPlugin, PluginResult, Requirement
from deepview.plugins.base import register_plugin


def _build_ecc(kind: str) -> Any | None:
    try:
        if kind == "hamming":
            from deepview.storage.ecc.hamming import HammingDecoder

            return HammingDecoder()
        if kind == "bch8":
            from deepview.storage.ecc.bch import BCHDecoder

            return BCHDecoder(t=8)
        if kind == "rs":
            from deepview.storage.ecc.reed_solomon import ReedSolomonDecoder

            return ReedSolomonDecoder()
    except (ImportError, RuntimeError):
        return None
    return None


def _build_ftl(kind: str, geometry: Any) -> Any | None:
    try:
        if kind == "ubi":
            from deepview.storage.ftl.ubi import UBITranslator

            return UBITranslator(geometry)
        if kind == "jffs2":
            from deepview.storage.ftl.jffs2 import JFFS2Translator

            return JFFS2Translator(geometry)
        if kind == "mtd":
            from deepview.storage.ftl.mtd import MTDPassthroughTranslator

            return MTDPassthroughTranslator(geometry)
        if kind == "badblock":
            from deepview.storage.ftl.badblock import BadBlockRemapTranslator

            return BadBlockRemapTranslator(geometry)
    except ImportError:
        return None
    return None


@register_plugin(
    name="nand_decode",
    category=PluginCategory.ARTIFACT_RECOVERY,
    description="Walk a NAND layer with ECC+FTL and report corrected/uncorrectable stats",
    tags=["nand", "ecc", "ftl", "artifact"],
)
class NANDDecodePlugin(DeepViewPlugin):

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(name="layer_name", description="Registered raw NAND DataLayer"),
            Requirement(
                name="page_size", description="Page size bytes", required=False, default=2048
            ),
            Requirement(
                name="spare_size", description="Spare area bytes", required=False, default=64
            ),
            Requirement(
                name="pages_per_block",
                description="Pages per erase block",
                required=False,
                default=64,
            ),
            Requirement(
                name="blocks", description="Total blocks", required=False, default=2048
            ),
            Requirement(
                name="ecc", description="ECC backend (bch8/hamming/rs)", required=False, default="bch8"
            ),
            Requirement(
                name="ftl", description="FTL backend (ubi/jffs2/mtd/badblock)", required=False, default="ubi"
            ),
            Requirement(
                name="spare_layout",
                description="Spare layout preset",
                required=False,
                default="onfi",
            ),
        ]

    def run(self) -> PluginResult:
        from deepview.core.exceptions import LayerError
        from deepview.interfaces.layer import DataLayer
        from deepview.storage.geometry import NANDGeometry, SpareLayout
        from deepview.storage.manager import StorageError

        layer_name = self.config.get("layer_name")
        if not layer_name:
            return PluginResult(columns=["Error"], rows=[{"Error": "layer_name is required"}])

        try:
            page_size = int(self.config.get("page_size", 2048))
            spare_size = int(self.config.get("spare_size", 64))
            pages_per_block = int(self.config.get("pages_per_block", 64))
            blocks = int(self.config.get("blocks", 2048))
        except (TypeError, ValueError) as e:
            return PluginResult(columns=["Error"], rows=[{"Error": f"bad int: {e}"}])

        ecc_kind = str(self.config.get("ecc", "bch8"))
        ftl_kind = str(self.config.get("ftl", "ubi"))
        layout_kind = str(self.config.get("spare_layout", "onfi"))

        try:
            obj = self.context.layers.get(layer_name)
        except LayerError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])
        if not isinstance(obj, DataLayer):
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"layer {layer_name!r} is not a DataLayer"}],
            )

        # Build the spare layout.
        layout: SpareLayout
        if layout_kind == "onfi":
            layout = SpareLayout.onfi(spare_size=spare_size)
        else:
            try:
                from deepview.storage.ecc import layouts as _layouts

                builder = getattr(_layouts, layout_kind, None)
                if builder is None:
                    return PluginResult(
                        columns=["Error"],
                        rows=[{"Error": f"unknown spare_layout {layout_kind!r}"}],
                    )
                layout = builder(spare_size=spare_size)
            except ImportError:
                layout = SpareLayout.onfi(spare_size=spare_size)

        geometry = NANDGeometry(
            page_size=page_size,
            spare_size=spare_size,
            pages_per_block=pages_per_block,
            blocks=blocks,
            spare_layout=layout,
        )

        ecc_instance = _build_ecc(ecc_kind)
        if ecc_instance is None:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"ecc backend {ecc_kind!r} unavailable"}],
                metadata={"ecc": ecc_kind, "available": False},
            )
        ftl_instance = _build_ftl(ftl_kind, geometry)
        if ftl_instance is None:
            return PluginResult(
                columns=["Error"],
                rows=[{"Error": f"ftl backend {ftl_kind!r} unavailable"}],
                metadata={"ftl": ftl_kind, "available": False},
            )

        try:
            wrapped = self.context.storage.wrap_nand(
                obj, geometry, ecc=ecc_instance, ftl=ftl_instance
            )
        except StorageError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])
        except ValueError as e:
            return PluginResult(columns=["Error"], rows=[{"Error": str(e)}])

        # Walk every page through the ECC layer to populate stats.
        ecc_layer = None
        try:
            from deepview.storage.ecc.base import ECCDataLayer

            # Descend the composition chain looking for our ECC layer.
            probe: Any = wrapped
            while probe is not None:
                if isinstance(probe, ECCDataLayer):
                    ecc_layer = probe
                    break
                probe = getattr(probe, "_backing", None)
        except ImportError:
            pass

        pages_walked = 0
        if ecc_layer is not None:
            total_pages = geometry.total_pages
            for page_idx in range(total_pages):
                try:
                    ecc_layer._read_page_data(page_idx)  # noqa: SLF001 - intentional API use
                except Exception:
                    continue
                pages_walked += 1

        stats: dict[str, int] = {"corrected": 0, "uncorrectable": 0, "pages_read": 0}
        if ecc_layer is not None:
            stats.update(ecc_layer.error_stats())

        # Count bad blocks by asking the FTL translator, if it exposes them.
        bad_blocks = 0
        bb = getattr(ftl_instance, "_bad_blocks", None)
        if isinstance(bb, set):
            bad_blocks = len(bb)

        rows = [
            {"Metric": "chip_total_pages", "Value": str(geometry.total_pages)},
            {"Metric": "chip_total_blocks", "Value": str(geometry.blocks)},
            {"Metric": "chip_page_size", "Value": str(geometry.page_size)},
            {"Metric": "chip_spare_size", "Value": str(geometry.spare_size)},
            {"Metric": "ecc_backend", "Value": ecc_kind},
            {"Metric": "ftl_backend", "Value": ftl_kind},
            {"Metric": "pages_walked", "Value": str(pages_walked)},
            {"Metric": "corrected", "Value": str(stats.get("corrected", 0))},
            {"Metric": "uncorrectable", "Value": str(stats.get("uncorrectable", 0))},
            {"Metric": "pages_read", "Value": str(stats.get("pages_read", 0))},
            {"Metric": "bad_blocks", "Value": str(bad_blocks)},
        ]

        metadata: dict[str, Any] = {
            "corrected": stats.get("corrected", 0),
            "uncorrectable": stats.get("uncorrectable", 0),
            "pages_read": stats.get("pages_read", 0),
            "bad_blocks": bad_blocks,
        }

        return PluginResult(
            columns=["Metric", "Value"],
            rows=rows,
            metadata=metadata,
        )
