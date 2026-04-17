"""Top-level convenience opener for a forensic image.

The :func:`auto_open` entry point walks the full Deep View storage stack in
one call: format detection -> raw :class:`DataLayer` -> optional NAND
ECC/FTL wrap -> partition parse -> per-partition filesystem probe.

Every optional dependency is lazy-loaded from inside guarded blocks, so the
core install without storage extras still imports this module cleanly and
the helper degrades gracefully by emitting human-readable notes instead of
raising.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from collections.abc import Sequence

    from deepview.core.context import AnalysisContext
    from deepview.interfaces.ecc import ECCDecoder
    from deepview.interfaces.filesystem import Filesystem
    from deepview.interfaces.ftl import FTLTranslator
    from deepview.storage.geometry import NANDGeometry
    from deepview.storage.partition import Partition


# ---------------------------------------------------------------------------
# Result bundle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AutoOpenResult:
    """Outcome of a one-shot auto-open of a forensic image."""

    raw_layer: DataLayer
    transformed_layer: DataLayer  # post-ECC/FTL/decryption (== raw if no transforms)
    partitions: tuple["Partition", ...] = ()
    filesystems: dict[int, "Filesystem"] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Internal lookup tables (populated lazily on first call)
# ---------------------------------------------------------------------------


def _build_ecc_decoder(name: str, geometry: "NANDGeometry") -> "ECCDecoder":
    """Construct an :class:`ECCDecoder` from a user-facing short name.

    Every import is deferred to call time so the core install imports cleanly
    without the ``ecc`` extra.
    """
    key = name.lower().strip()
    if key in ("hamming", "hamming256"):
        from deepview.storage.ecc.hamming import HammingDecoder

        return HammingDecoder()
    if key.startswith("bch"):
        # Accept "bch", "bch4", "bch8", "bch16".
        t_str = key[3:] or "8"
        try:
            t = int(t_str)
        except ValueError as exc:
            raise ValueError(f"unparseable BCH strength in {name!r}") from exc
        from deepview.storage.ecc.bch import BCHDecoder

        return BCHDecoder(t=t)
    if key in ("rs", "reed_solomon", "reedsolomon", "reed-solomon"):
        from deepview.storage.ecc.reed_solomon import ReedSolomonDecoder

        return ReedSolomonDecoder()
    raise ValueError(f"unknown ECC decoder: {name!r}")


def _build_ftl_translator(name: str, geometry: "NANDGeometry") -> "FTLTranslator":
    """Construct an :class:`FTLTranslator` from a short name."""
    key = name.lower().strip()
    if key == "ubi":
        from deepview.storage.ftl.ubi import UBITranslator

        return UBITranslator(geometry)
    if key == "jffs2":
        from deepview.storage.ftl.jffs2 import JFFS2Translator

        return JFFS2Translator(geometry)
    if key == "mtd":
        from deepview.storage.ftl.mtd import MTDPassthroughTranslator

        return MTDPassthroughTranslator(geometry)
    if key in ("badblock", "bad_block", "bad-block"):
        from deepview.storage.ftl.badblock import BadBlockRemapTranslator

        return BadBlockRemapTranslator(geometry)
    if key in ("emmc", "emmc_hints"):
        from deepview.storage.ftl.emmc_hints import EMMCHintTranslator

        return EMMCHintTranslator(geometry)
    if key == "ufs":
        from deepview.storage.ftl.ufs import UFSTranslator

        return UFSTranslator(geometry)
    raise ValueError(f"unknown FTL translator: {name!r}")


def _apply_spare_layout(
    geometry: "NANDGeometry",
    spare_layout: str | None,
) -> "NANDGeometry":
    """Return a copy of *geometry* with ``spare_layout`` resolved if requested.

    If *spare_layout* is ``None`` the geometry is returned unchanged. Otherwise
    a named preset (``"onfi"`` / ``"linear"``) is resolved via
    :class:`~deepview.storage.geometry.SpareLayout`.
    """
    from dataclasses import replace

    from deepview.storage.geometry import SpareLayout

    if spare_layout is None:
        return geometry
    key = spare_layout.lower().strip()
    if key == "onfi":
        layout = SpareLayout.onfi(spare_size=geometry.spare_size)
    elif key == "linear":
        # Pick a conservative 14-byte ECC tail if not already described.
        ecc_bytes = min(14, max(1, geometry.spare_size // 4))
        layout = SpareLayout.linear_ecc(
            spare_size=geometry.spare_size, ecc_bytes=ecc_bytes
        )
    else:
        raise ValueError(f"unknown spare layout: {spare_layout!r}")
    return replace(geometry, spare_layout=layout)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def auto_open(
    context: "AnalysisContext",
    path: Path,
    *,
    nand_geometry: "NANDGeometry | None" = None,
    ecc: str | None = None,
    ftl: str | None = None,
    spare_layout: str | None = None,
    open_filesystems: bool = True,
) -> AutoOpenResult:
    """Open *path* end-to-end through the storage stack.

    Pipeline:
        1. Detect the dump format via :class:`MemoryManager`; build the raw
           :class:`DataLayer`.
        2. If *nand_geometry* is supplied, optionally wrap with an
           :class:`ECCDataLayer` + :class:`LinearizedFlashLayer` via
           :meth:`StorageManager.wrap_nand`.
        3. Detect partitions on the (possibly transformed) layer via
           :func:`deepview.storage.partition.parse_partitions`.
        4. For each partition, attempt to auto-probe its filesystem via
           :meth:`StorageManager.open_filesystem`. Failures are recorded in
           ``notes`` but never raise.
        5. Return an :class:`AutoOpenResult` bundle.

    All optional dependencies are lazy-loaded; anything unavailable becomes a
    ``notes`` entry instead of a hard error.
    """
    notes: list[str] = []

    # ------------------------------------------------------------------
    # 1. Build the raw layer via MemoryManager (lazy import).
    # ------------------------------------------------------------------
    from deepview.memory.manager import MemoryManager

    manager = MemoryManager(context)
    raw_layer: DataLayer = manager.open_layer(path)

    # ------------------------------------------------------------------
    # 2. Optionally wrap with ECC / FTL.
    # ------------------------------------------------------------------
    transformed_layer: DataLayer = raw_layer
    if nand_geometry is not None:
        try:
            geometry = _apply_spare_layout(nand_geometry, spare_layout)
        except Exception as exc:
            notes.append(f"spare_layout {spare_layout!r} not applied: {exc}")
            geometry = nand_geometry

        ecc_decoder: ECCDecoder | None = None
        if ecc is not None:
            try:
                ecc_decoder = _build_ecc_decoder(ecc, geometry)
            except Exception as exc:
                notes.append(f"ecc {ecc!r} unavailable: {exc}")

        ftl_translator: FTLTranslator | None = None
        if ftl is not None:
            try:
                ftl_translator = _build_ftl_translator(ftl, geometry)
            except Exception as exc:
                notes.append(f"ftl {ftl!r} unavailable: {exc}")

        try:
            transformed_layer = context.storage.wrap_nand(
                raw_layer,
                geometry,
                ecc=ecc_decoder,
                ftl=ftl_translator,
            )
        except Exception as exc:
            notes.append(f"wrap_nand failed, using raw layer: {exc}")
            transformed_layer = raw_layer

    # ------------------------------------------------------------------
    # 3. Partition detection.
    # ------------------------------------------------------------------
    partitions: list[Partition] = []
    try:
        from deepview.storage.partition import parse_partitions

        partitions = list(parse_partitions(transformed_layer))
    except Exception as exc:
        notes.append(f"partition parse failed: {exc}")

    # ------------------------------------------------------------------
    # 4. Per-partition filesystem probing.
    # ------------------------------------------------------------------
    filesystems: dict[int, Filesystem] = {}
    if open_filesystems and partitions:
        from deepview.storage.partition import PartitionLayer

        for part in partitions:
            try:
                part_layer = PartitionLayer(
                    transformed_layer, part.start_offset, part.size
                )
            except Exception as exc:
                notes.append(
                    f"partition[{part.index}] slice failed: {exc}"
                )
                continue
            try:
                fs = context.storage.open_filesystem(part_layer)
            except Exception as exc:
                notes.append(
                    f"partition[{part.index}] filesystem probe: {exc}"
                )
                continue
            filesystems[part.index] = fs

    return AutoOpenResult(
        raw_layer=raw_layer,
        transformed_layer=transformed_layer,
        partitions=tuple(partitions),
        filesystems=dict(filesystems),
        notes=tuple(notes),
    )


def auto_unlock_and_open(
    context: "AnalysisContext",
    path: Path,
    *,
    nand_geometry: "NANDGeometry | None" = None,
    ecc: str | None = None,
    ftl: str | None = None,
    spare_layout: str | None = None,
    open_filesystems: bool = True,
    passphrases: "Sequence[str]" = (),
    scan_keys: bool = True,
    try_hidden: bool = False,
) -> AutoOpenResult:
    """Variant of :func:`auto_open` that runs :meth:`UnlockOrchestrator.auto_unlock`
    on the transformed layer before partition detection.

    If the unlocker is unavailable or returns no decrypted layers, the call
    falls through to exactly the same result as :func:`auto_open`. When at
    least one decrypted layer is produced, the *first* one replaces the
    transformed layer for the subsequent partition / filesystem steps.
    """
    notes: list[str] = []

    from deepview.memory.manager import MemoryManager

    manager = MemoryManager(context)
    raw_layer: DataLayer = manager.open_layer(path)

    transformed_layer: DataLayer = raw_layer
    if nand_geometry is not None:
        try:
            geometry = _apply_spare_layout(nand_geometry, spare_layout)
        except Exception as exc:
            notes.append(f"spare_layout {spare_layout!r} not applied: {exc}")
            geometry = nand_geometry

        ecc_decoder: ECCDecoder | None = None
        if ecc is not None:
            try:
                ecc_decoder = _build_ecc_decoder(ecc, geometry)
            except Exception as exc:
                notes.append(f"ecc {ecc!r} unavailable: {exc}")

        ftl_translator: FTLTranslator | None = None
        if ftl is not None:
            try:
                ftl_translator = _build_ftl_translator(ftl, geometry)
            except Exception as exc:
                notes.append(f"ftl {ftl!r} unavailable: {exc}")

        try:
            transformed_layer = context.storage.wrap_nand(
                raw_layer,
                geometry,
                ecc=ecc_decoder,
                ftl=ftl_translator,
            )
        except Exception as exc:
            notes.append(f"wrap_nand failed, using raw layer: {exc}")
            transformed_layer = raw_layer

    # ------------------------------------------------------------------
    # Unlock pass — entirely best-effort. Any missing dep / async runner
    # failure simply falls through with a note.
    # ------------------------------------------------------------------
    try:
        unlocker = context.unlocker
    except Exception as exc:
        unlocker = None
        notes.append(f"unlocker unavailable: {exc}")

    if unlocker is not None:
        unlocked_layers: list[Any] = []
        try:
            import asyncio

            coro = unlocker.auto_unlock(
                transformed_layer,
                passphrases=tuple(passphrases),
                scan_keys=scan_keys,
                try_hidden=try_hidden,
            )
            try:
                # If we're already inside a running loop (unusual for a CLI
                # call but possible in tests), fall back to a fresh loop via
                # ``asyncio.run`` in a worker thread.
                asyncio.get_running_loop()
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    unlocked_layers = ex.submit(asyncio.run, coro).result()
            except RuntimeError:
                unlocked_layers = asyncio.run(coro)
        except Exception as exc:
            notes.append(f"auto_unlock failed: {exc}")
            unlocked_layers = []

        if unlocked_layers:
            first = unlocked_layers[0]
            if isinstance(first, DataLayer):
                transformed_layer = first
            else:
                notes.append("auto_unlock returned non-DataLayer result")

    # ------------------------------------------------------------------
    # Partition detection + filesystem probing (same as auto_open step 3-4)
    # ------------------------------------------------------------------
    partitions: list[Partition] = []
    try:
        from deepview.storage.partition import parse_partitions

        partitions = list(parse_partitions(transformed_layer))
    except Exception as exc:
        notes.append(f"partition parse failed: {exc}")

    filesystems: dict[int, Filesystem] = {}
    if open_filesystems and partitions:
        from deepview.storage.partition import PartitionLayer

        for part in partitions:
            try:
                part_layer = PartitionLayer(
                    transformed_layer, part.start_offset, part.size
                )
            except Exception as exc:
                notes.append(
                    f"partition[{part.index}] slice failed: {exc}"
                )
                continue
            try:
                fs = context.storage.open_filesystem(part_layer)
            except Exception as exc:
                notes.append(
                    f"partition[{part.index}] filesystem probe: {exc}"
                )
                continue
            filesystems[part.index] = fs

    return AutoOpenResult(
        raw_layer=raw_layer,
        transformed_layer=transformed_layer,
        partitions=tuple(partitions),
        filesystems=dict(filesystems),
        notes=tuple(notes),
    )


__all__ = ["AutoOpenResult", "auto_open", "auto_unlock_and_open"]
