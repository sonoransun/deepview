"""Encrypted-container detection + unlock orchestration.

The :class:`UnlockOrchestrator` is the top-level entry point. It keeps a
registry of :class:`Unlocker` adapters (LUKS / BitLocker / VeraCrypt /
FileVault2 in later slices) and tries every registered adapter against a
given :class:`DataLayer`. For each detected container it attempts:

1. ``MasterKey`` candidates harvested from memory (cheap — just a
   symmetric AES decrypt).
2. ``Keyfile`` candidates.
3. ``Passphrase`` candidates, with KDF work routed through the
   :class:`~deepview.offload.engine.OffloadEngine` so PBKDF2 / Argon2id
   never blocks the caller thread.

Every attempt publishes :class:`ContainerUnlockStartedEvent` /
:class:`ContainerUnlockProgressEvent` / :class:`ContainerUnlockedEvent` /
:class:`ContainerUnlockFailedEvent` onto :attr:`AnalysisContext.events`
so dashboards / replay / CLI renderers can follow along.
"""
from __future__ import annotations

import hashlib
import importlib
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from deepview.core.events import (
    ContainerUnlockedEvent,
    ContainerUnlockFailedEvent,
    ContainerUnlockProgressEvent,
    ContainerUnlockStartedEvent,
)
from deepview.interfaces.layer import DataLayer
from deepview.storage.containers.layer import DecryptedVolumeLayer

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.offload.engine import OffloadEngine

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContainerHeader:
    """Generic detected-container record returned by ``Unlocker.detect``.

    Adapter-specific fields travel inside ``kdf_params`` or ``raw``.
    """

    format: str
    cipher: str
    sector_size: int
    data_offset: int
    data_length: int
    kdf: str
    kdf_params: dict[str, object] = field(default_factory=dict)
    raw: bytes = b""


# ---------------------------------------------------------------------------
# Key sources
# ---------------------------------------------------------------------------


class KeySource(ABC):
    """Abstract provider of a master-key-equivalent byte string."""

    @abstractmethod
    async def derive(
        self, engine: OffloadEngine, header: ContainerHeader
    ) -> bytes:
        """Return the cipher key material for *header* using *engine* if needed."""


@dataclass(frozen=True)
class MasterKey(KeySource):
    """A pre-known master key (e.g. extracted from memory)."""

    key: bytes

    async def derive(
        self, engine: OffloadEngine, header: ContainerHeader
    ) -> bytes:
        return self.key


@dataclass(frozen=True)
class Passphrase(KeySource):
    """A user passphrase that must be run through the container's KDF."""

    passphrase: str

    async def derive(
        self, engine: OffloadEngine, header: ContainerHeader
    ) -> bytes:
        # Lazy import so module load does not depend on the offload slice
        # shipping in lockstep.
        from deepview.offload.jobs import make_job

        if header.kdf == "argon2id":
            callable_ref = "deepview.offload.kdf:argon2id"
        else:
            callable_ref = "deepview.offload.kdf:pbkdf2_sha256"

        kdf_params = header.kdf_params
        payload = {
            "password": self.passphrase,
            "salt": kdf_params.get("salt", b""),
            "iterations": kdf_params.get("iterations", 1000),
            "dklen": kdf_params.get("dklen", 32),
        }

        # Emit progress before submitting so listeners see the attempt
        # flight-in even if the offload engine blocks. Prefer the
        # public ``engine.events`` accessor; fall back to
        # ``engine.context.events`` for test stubs that predate the
        # ``events`` property.
        bus = getattr(engine, "events", None)
        if bus is None:
            ctx_obj = getattr(engine, "context", None)
            bus = getattr(ctx_obj, "events", None) if ctx_obj else None
        if bus is not None:
            try:
                bus.publish(
                    ContainerUnlockProgressEvent(
                        format=header.format,
                        stage="kdf",
                        attempted=1,
                        total=1,
                    )
                )
            except Exception as exc:  # noqa: BLE001 — progress is best-effort
                _logger.debug(
                    "ContainerUnlockProgressEvent publish failed: %s", exc
                )

        job = make_job(
            kind=header.kdf or "pbkdf2_sha256",
            payload=payload,
            callable_ref=callable_ref,
        )
        future = engine.submit(job)
        result = future.await_result()
        if not result.ok:
            raise RuntimeError(
                f"KDF offload failed for {header.format}: {result.error}"
            )
        output = result.output
        if not isinstance(output, (bytes, bytearray)):
            raise RuntimeError(
                f"KDF offload for {header.format} returned non-bytes result"
            )
        return bytes(output)


@dataclass(frozen=True)
class Keyfile(KeySource):
    """A keyfile hashed with SHA-256 (LUKS / VeraCrypt convention)."""

    path: Path

    async def derive(
        self, engine: OffloadEngine, header: ContainerHeader
    ) -> bytes:
        data = Path(self.path).read_bytes()
        return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Unlocker ABC
# ---------------------------------------------------------------------------


class Unlocker(ABC):
    """Abstract per-format container unlocker."""

    format_name: ClassVar[str] = ""

    @abstractmethod
    def detect(
        self, layer: DataLayer, offset: int = 0
    ) -> ContainerHeader | None:
        """Return a :class:`ContainerHeader` if *layer* holds this format."""

    @abstractmethod
    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> DecryptedVolumeLayer:
        """Produce a :class:`DecryptedVolumeLayer` over the plaintext extent."""


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


# Concrete adapter modules live in sibling files (slices 15-17). Each
# module is expected to expose a module-level ``UNLOCKER`` attribute set
# to a class (subclass of :class:`Unlocker`). Missing modules are skipped.
_AUTO_DISCOVER_MODULES: tuple[str, ...] = (
    "deepview.storage.containers.luks",
    "deepview.storage.containers.bitlocker",
    "deepview.storage.containers.filevault2",
    "deepview.storage.containers.veracrypt",
)


class UnlockOrchestrator:
    """Coordinates detection + multi-key unlock attempts across adapters."""

    def __init__(self, context: AnalysisContext) -> None:
        self._context = context
        self._unlockers: list[Unlocker] = []
        self._discover_builtin()

    # ------------------------------------------------------------------
    # Registration / discovery
    # ------------------------------------------------------------------

    def _discover_builtin(self) -> None:
        """Import each known adapter module and register its ``UNLOCKER``."""
        for mod_name in _AUTO_DISCOVER_MODULES:
            try:
                mod = importlib.import_module(mod_name)
            except ImportError as exc:
                _logger.info(
                    "container unlocker module %s unavailable: %s", mod_name, exc
                )
                continue
            unlocker_cls = getattr(mod, "UNLOCKER", None)
            if unlocker_cls is None:
                continue
            try:
                self.register(unlocker_cls())
            except (ImportError, RuntimeError, TypeError) as exc:
                # An adapter that fails to instantiate (e.g. missing
                # optional dep at __init__) is skipped. The CLI doctor
                # command surfaces the logged INFO record.
                _logger.info(
                    "container unlocker %s failed to initialise: %s",
                    mod_name,
                    exc,
                )
                continue

    def register(self, unlocker: Unlocker) -> None:
        self._unlockers.append(unlocker)

    def available_unlockers(self) -> list[str]:
        return [u.format_name or type(u).__name__ for u in self._unlockers]

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    async def auto_unlock(
        self,
        layer: DataLayer,
        *,
        passphrases: Sequence[str] = (),
        keyfiles: Sequence[Path] = (),
        scan_keys: bool = True,
        try_hidden: bool = False,
    ) -> list[DecryptedVolumeLayer]:
        """Detect containers on *layer* and try every candidate key source.

        Returns every successfully-unlocked :class:`DecryptedVolumeLayer`.
        """
        results: list[DecryptedVolumeLayer] = []
        bus = self._context.events

        master_key_candidates: list[MasterKey] = []
        if scan_keys:
            master_key_candidates = self._collect_memory_keys()

        keyfile_candidates = [Keyfile(path=Path(p)) for p in keyfiles]
        passphrase_candidates = [Passphrase(passphrase=p) for p in passphrases]

        for unlocker in self._unlockers:
            header = None
            try:
                header = unlocker.detect(layer)
            except Exception as exc:  # noqa: BLE001 — detect is fail-open
                _logger.info(
                    "unlocker %s detect() raised: %s",
                    unlocker.format_name or type(unlocker).__name__,
                    exc,
                )
                header = None
            if header is None:
                continue

            layer_name = self._layer_name(layer)
            ordered_sources: list[tuple[str, KeySource]] = []
            expected_keylen = self._expected_key_length(header)
            for mk in master_key_candidates:
                if expected_keylen and len(mk.key) != expected_keylen:
                    continue
                ordered_sources.append(("master_key", mk))
            for kf in keyfile_candidates:
                ordered_sources.append(("keyfile", kf))
            for pp in passphrase_candidates:
                ordered_sources.append(("passphrase", pp))

            unlocked_layer = await self._try_sources(
                unlocker=unlocker,
                layer=layer,
                header=header,
                layer_name=layer_name,
                sources=ordered_sources,
                try_hidden=try_hidden,
            )
            if unlocked_layer is not None:
                results.append(unlocked_layer)
                continue

            bus.publish(
                ContainerUnlockFailedEvent(
                    format=header.format,
                    layer=layer_name,
                    reason="all candidate keys exhausted",
                )
            )

        return results

    async def _try_sources(
        self,
        *,
        unlocker: Unlocker,
        layer: DataLayer,
        header: ContainerHeader,
        layer_name: str,
        sources: Sequence[tuple[str, KeySource]],
        try_hidden: bool,
    ) -> DecryptedVolumeLayer | None:
        bus = self._context.events
        for source_kind, source in sources:
            started = time.monotonic()
            bus.publish(
                ContainerUnlockStartedEvent(
                    format=header.format,
                    layer=layer_name,
                    key_source=source_kind,
                )
            )
            try:
                unlocked = await unlocker.unlock(
                    layer, header, source, try_hidden=try_hidden
                )
            except Exception:
                continue
            elapsed = time.monotonic() - started
            produced = unlocked.metadata.name
            bus.publish(
                ContainerUnlockedEvent(
                    format=header.format,
                    layer=layer_name,
                    produced_layer=produced,
                    elapsed_s=elapsed,
                )
            )
            return unlocked
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _layer_name(self, layer: DataLayer) -> str:
        try:
            return layer.metadata.name
        except Exception:
            return type(layer).__name__

    def _expected_key_length(self, header: ContainerHeader) -> int | None:
        raw = header.kdf_params.get("dklen") if header.kdf_params else None
        if isinstance(raw, int) and raw > 0:
            return raw
        return None

    def _collect_memory_keys(self) -> list[MasterKey]:
        """Scan every registered layer for AES key findings."""
        try:
            from deepview.detection.encryption_keys import EncryptionKeyScanner
        except Exception:
            return []

        scanner = EncryptionKeyScanner()
        master_keys: list[MasterKey] = []
        for name in self._context.layers.list_layers():
            try:
                layer = self._context.layers.get(name)
            except Exception:
                continue
            if not isinstance(layer, DataLayer):
                continue
            try:
                size = layer.maximum_address + 1
            except Exception:
                continue
            if size <= 0:
                continue
            chunk = min(size, 1 << 20)
            try:
                data = layer.read(0, chunk, pad=True)
            except Exception:
                continue
            try:
                findings = scanner.scan_aes_keys(data, offset=0)
            except Exception:
                findings = []
            for finding in findings:
                master_keys.append(MasterKey(key=bytes(finding.key_data)))
        return master_keys


__all__ = [
    "ContainerHeader",
    "KeySource",
    "MasterKey",
    "Passphrase",
    "Keyfile",
    "Unlocker",
    "UnlockOrchestrator",
]
