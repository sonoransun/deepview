"""Inventory encrypted containers across registered layers.

For every layer currently registered on the :class:`AnalysisContext`
(or a comma-separated subset supplied via the ``layers`` config), this
plugin asks each :class:`Unlocker` advertised by the
:class:`UnlockOrchestrator` whether it recognises the layer's bytes as a
known container format. For memory-typed layers (heuristic match on the
registered name or the layer's ``os`` metadata hint) it also runs the
:class:`EncryptionKeyScanner` and classifies candidate keys by the
matched header's declared cipher so the operator can see both the
container and the key candidates that might unlock it.

The plugin is intentionally read-only: it never calls
``unlocker.unlock``, never submits KDF work to the offload engine, and
never mutates the layer registry. It is safe to run on a live analysis
session without side effects.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from deepview.storage.containers.unlock import ContainerHeader


log = get_logger("plugins.volume_unlock")


_MEMORY_NAME_HINTS = ("mem", "ram", "vmem", "lime", "dump")


@register_plugin(
    name="volume_unlock",
    category=PluginCategory.CREDENTIALS,
    description=(
        "Inventory encrypted containers across registered layers; "
        "show candidate keys."
    ),
    tags=["unlock", "crypto", "containers"],
)
class VolumeUnlockPlugin(DeepViewPlugin):
    """List every detected encrypted container and candidate memory keys."""

    @classmethod
    def get_requirements(cls) -> list[Requirement]:
        return [
            Requirement(
                name="layers",
                description=(
                    "Comma-separated list of layer names to inventory "
                    "('all' for everything)"
                ),
                required=False,
                requirement_type=RequirementType.CONFIG,
                default="all",
            ),
            Requirement(
                name="scan_keys",
                description="Run encryption-key scanner on memory layers",
                required=False,
                requirement_type=RequirementType.CONFIG,
                default=True,
            ),
        ]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self) -> PluginResult:
        columns = [
            "Layer",
            "Format",
            "Cipher",
            "CandidateKeys",
            "DataOffset",
            "DataLength",
        ]

        try:
            from deepview.storage.containers.unlock import UnlockOrchestrator
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("unlock_orchestrator_unavailable", error=str(exc))
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": "Unlock orchestrator not available"},
            )

        scanner_cls: type | None
        try:
            from deepview.detection.encryption_keys import (
                EncryptionKeyScanner as _Scanner,
            )

            scanner_cls = _Scanner
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("encryption_key_scanner_unavailable", error=str(exc))
            scanner_cls = None

        try:
            orchestrator = UnlockOrchestrator(self.context)
        except Exception as exc:
            log.debug("orchestrator_instantiation_failed", error=str(exc))
            return PluginResult(
                columns=columns,
                rows=[],
                metadata={"error": "Unlock orchestrator not available"},
            )

        layer_names = self._resolve_layer_names()
        scan_keys = self._coerce_bool(self.config.get("scan_keys", True))

        unlockers: list[Any] = list(getattr(orchestrator, "_unlockers", []))

        rows: list[dict[str, Any]] = []
        total_detected = 0
        total_layers = 0

        for name in layer_names:
            total_layers += 1
            try:
                layer = self.context.layers.get(name)
            except Exception as exc:
                log.debug("layer_fetch_failed", layer=name, error=str(exc))
                continue
            if not isinstance(layer, DataLayer):
                continue

            headers = self._detect_headers(unlockers, layer, name)
            if not headers:
                continue

            if (
                scan_keys
                and scanner_cls is not None
                and self._is_memory_layer(name, layer)
            ):
                key_counts_by_cipher = self._count_keys_by_cipher(
                    scanner_cls(), layer, headers
                )
            else:
                key_counts_by_cipher = {h.cipher: 0 for h in headers}

            for header in headers:
                total_detected += 1
                rows.append(
                    {
                        "Layer": name,
                        "Format": header.format,
                        "Cipher": header.cipher,
                        "CandidateKeys": str(
                            key_counts_by_cipher.get(header.cipher, 0)
                        ),
                        "DataOffset": f"0x{header.data_offset:x}",
                        "DataLength": str(header.data_length),
                    }
                )

        metadata: dict[str, Any] = {
            "layers_scanned": total_layers,
            "containers_detected": total_detected,
            "unlockers_available": orchestrator.available_unlockers(),
        }
        return PluginResult(columns=columns, rows=rows, metadata=metadata)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_layer_names(self) -> list[str]:
        raw = self.config.get("layers", "all")
        if raw is None:
            return list(self.context.layers.list_layers())
        if isinstance(raw, (list, tuple)):
            names = [str(n).strip() for n in raw if str(n).strip()]
        else:
            names = [
                piece.strip()
                for piece in str(raw).split(",")
                if piece.strip()
            ]
        if not names or any(n.lower() == "all" for n in names):
            return list(self.context.layers.list_layers())
        return [n for n in names if self.context.layers.has(n)]

    @staticmethod
    def _coerce_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _is_memory_layer(name: str, layer: DataLayer) -> bool:
        lower = name.lower()
        if any(hint in lower for hint in _MEMORY_NAME_HINTS):
            return True
        try:
            meta = layer.metadata
        except Exception:
            return False
        os_hint = getattr(meta, "os", "") or ""
        return bool(os_hint)

    def _detect_headers(
        self,
        unlockers: list[Any],
        layer: DataLayer,
        layer_name: str,
    ) -> list[ContainerHeader]:
        headers: list[ContainerHeader] = []
        for unlocker in unlockers:
            try:
                header = unlocker.detect(layer)
            except Exception as exc:
                log.debug(
                    "unlocker_detect_failed",
                    layer=layer_name,
                    unlocker=type(unlocker).__name__,
                    error=str(exc),
                )
                continue
            if header is None:
                continue
            headers.append(header)
        return headers

    def _count_keys_by_cipher(
        self,
        scanner: Any,
        layer: DataLayer,
        headers: list[ContainerHeader],
    ) -> dict[str, int]:
        counts: dict[str, int] = {h.cipher: 0 for h in headers}
        try:
            size = layer.maximum_address + 1
        except Exception:
            return counts
        if size <= 0:
            return counts
        chunk = min(size, 1 << 20)
        try:
            data = layer.read(0, chunk, pad=True)
        except Exception as exc:
            log.debug("memory_layer_read_failed", error=str(exc))
            return counts
        try:
            findings = scanner.scan_all(data, offset=0)
        except Exception as exc:
            log.debug("scan_all_failed", error=str(exc))
            return counts

        for finding in findings:
            cipher_hint = self._classify_finding(finding)
            for header in headers:
                if cipher_hint and cipher_hint in header.cipher.lower():
                    counts[header.cipher] += 1
                elif not cipher_hint:
                    # Unclassified findings are counted against every
                    # detected header so the operator still sees a
                    # candidate-count signal.
                    counts[header.cipher] += 1
        return counts

    @staticmethod
    def _classify_finding(finding: Any) -> str:
        key_type = str(getattr(finding, "key_type", "")).lower()
        if key_type.startswith("aes"):
            return "aes"
        if key_type.startswith("rsa"):
            return "rsa"
        if "bitlocker" in key_type:
            return "aes"
        if "dm_crypt" in key_type or "dm-crypt" in key_type:
            return "aes"
        return ""
