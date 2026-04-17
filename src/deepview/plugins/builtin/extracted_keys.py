"""Run the encryption-key scanner on a registered memory layer.

Given a layer name, pull the bytes from the layer, feed them to
:class:`deepview.detection.encryption_keys.EncryptionKeyScanner`,
filter by confidence threshold and an allow-list of key types, record
each surviving finding in the context's :class:`ArtifactStore` under the
``encryption_keys`` category, and return a tabular summary.
"""
from __future__ import annotations

from typing import Any

from deepview.core.logging import get_logger
from deepview.core.types import PluginCategory
from deepview.interfaces.layer import DataLayer
from deepview.interfaces.plugin import (
    DeepViewPlugin,
    PluginResult,
    Requirement,
    RequirementType,
)
from deepview.plugins.base import register_plugin

log = get_logger("plugins.extracted_keys")


# Maps the normalized alias supplied by the user to the
# ``KeyFinding.key_type`` string emitted by ``EncryptionKeyScanner``.
_KEY_TYPE_ALIASES: dict[str, tuple[str, ...]] = {
    "aes-128": ("aes_128",),
    "aes-256": ("aes_256",),
    "rsa": ("rsa",),
    "bitlocker-fvek": ("bitlocker",),
    "dm-crypt": ("dm_crypt",),
}

_DEFAULT_CONFIDENCE = 0.7
_READ_CHUNK = 1 << 20  # 1 MiB window


@register_plugin(
    name="extracted_keys",
    category=PluginCategory.CREDENTIALS,
    description="Run the encryption-key scanner on a registered memory layer.",
    tags=["keys", "memory"],
)
class ExtractedKeysPlugin(DeepViewPlugin):
    """Surface cryptographic key material from a registered memory layer."""

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="layer_name",
                description=(
                    "Name of the registered layer to scan for key material"
                ),
                required=True,
                requirement_type=RequirementType.CONFIG,
            ),
            Requirement(
                name="confidence_threshold",
                description=(
                    "Minimum KeyFinding confidence (0.0-1.0) to include"
                ),
                required=False,
                requirement_type=RequirementType.CONFIG,
                default=_DEFAULT_CONFIDENCE,
            ),
            Requirement(
                name="key_types",
                description=(
                    "Comma-separated subset of aes-128, aes-256, rsa, "
                    "bitlocker-fvek, dm-crypt, or 'all'"
                ),
                required=False,
                requirement_type=RequirementType.CONFIG,
                default="all",
            ),
        ]

    def run(self) -> PluginResult:
        columns = [
            "KeyType",
            "Offset",
            "Confidence",
            "Description",
            "KeyDataPreview",
        ]

        layer_name = self.config.get("layer_name")
        if not layer_name:
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": "layer_name is required"},
            )

        try:
            layer = self.context.layers.get(str(layer_name))
        except Exception as exc:
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": f"layer not found: {exc}"},
            )
        if not isinstance(layer, DataLayer):
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": "registered object is not a DataLayer"},
            )

        try:
            from deepview.detection.encryption_keys import EncryptionKeyScanner
        except Exception as exc:  # pragma: no cover - defensive
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": f"EncryptionKeyScanner unavailable: {exc}"},
            )

        threshold = self._coerce_threshold(
            self.config.get("confidence_threshold", _DEFAULT_CONFIDENCE)
        )
        allowed_types = self._resolve_key_types(
            self.config.get("key_types", "all")
        )

        data = self._read_layer(layer)
        if data is None:
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": "failed to read layer bytes"},
            )

        scanner = EncryptionKeyScanner()
        try:
            findings = scanner.scan_all(data, offset=0)
        except Exception as exc:
            log.debug("scan_all_failed", error=str(exc))
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": f"scan failed: {exc}"},
            )

        rows: list[dict[str, Any]] = []
        for finding in findings:
            if finding.confidence < threshold:
                continue
            if allowed_types is not None and finding.key_type not in allowed_types:
                continue
            key_data = bytes(getattr(finding, "key_data", b"") or b"")
            preview = key_data[:16].hex()
            row = {
                "KeyType": finding.key_type,
                "Offset": f"0x{finding.offset:x}",
                "Confidence": f"{finding.confidence:.2f}",
                "Description": getattr(finding, "description", "") or "",
                "KeyDataPreview": preview,
            }
            rows.append(row)
            self.context.artifacts.add(
                "encryption_keys",
                {
                    "layer": str(layer_name),
                    "key_type": finding.key_type,
                    "offset": int(finding.offset),
                    "confidence": float(finding.confidence),
                    "description": getattr(finding, "description", "") or "",
                    "key_data_hex": key_data.hex(),
                },
            )

        return PluginResult(
            columns=columns,
            rows=rows,
            metadata={
                "layer": str(layer_name),
                "findings_total": len(findings),
                "findings_kept": len(rows),
                "confidence_threshold": threshold,
                "key_types": sorted(allowed_types)
                if allowed_types is not None
                else "all",
                "bytes_scanned": len(data),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_threshold(value: Any) -> float:
        try:
            threshold = float(value)
        except (TypeError, ValueError):
            threshold = _DEFAULT_CONFIDENCE
        if threshold < 0.0:
            threshold = 0.0
        elif threshold > 1.0:
            threshold = 1.0
        return threshold

    @staticmethod
    def _resolve_key_types(value: Any) -> set[str] | None:
        if value is None:
            return None
        if isinstance(value, (list, tuple, set)):
            aliases = [str(v).strip().lower() for v in value if str(v).strip()]
        else:
            aliases = [
                piece.strip().lower()
                for piece in str(value).split(",")
                if piece.strip()
            ]
        if not aliases or any(a == "all" for a in aliases):
            return None
        resolved: set[str] = set()
        for alias in aliases:
            mapped = _KEY_TYPE_ALIASES.get(alias)
            if mapped:
                resolved.update(mapped)
            else:
                # Accept a raw KeyFinding.key_type string too.
                resolved.add(alias)
        return resolved or None

    @staticmethod
    def _read_layer(layer: DataLayer) -> bytes | None:
        try:
            min_addr = layer.minimum_address
            max_addr = layer.maximum_address
        except Exception:
            return None
        size = max(0, max_addr - min_addr + 1)
        if size <= 0:
            return b""
        chunk = min(size, _READ_CHUNK)
        try:
            return layer.read(min_addr, chunk, pad=True)
        except Exception as exc:
            log.debug("layer_read_failed", error=str(exc))
            return None
