"""Storage subsystem CLI group.

Subcommands:

* ``storage info``  — probe a registered layer with every available adapter.
* ``storage wrap``  — compose RawNAND -> ECC -> FTL into a new DataLayer and
  register it under a new name.
* ``storage mount`` — open a filesystem over a registered layer and register
  the resulting :class:`~deepview.interfaces.filesystem.Filesystem` object in
  the layer registry under ``NAME-fs``.
* ``storage list``  — enumerate registered layers, adapters, and translators.

None of these commands require root. Every lazy import is guarded so that
users without the optional storage extras still see useful errors rather than
``ImportError`` tracebacks.
"""
from __future__ import annotations

from typing import Any

import click
from rich.console import Console
from rich.table import Table

from deepview.core.context import AnalysisContext
from deepview.interfaces.layer import DataLayer
from deepview.storage.filesystems.registry import register_all
from deepview.storage.geometry import NANDGeometry, SpareLayout
from deepview.storage.manager import StorageError


_ECC_CHOICES = ("bch8", "hamming", "rs")
_FTL_CHOICES = ("ubi", "jffs2", "mtd", "badblock")
_SPARE_CHOICES = ("onfi", "samsung_klm", "toshiba_tc58", "micron_mt29f")


@click.group("storage")
def storage() -> None:
    """Storage subsystem commands (NAND wrapping, filesystems, probing)."""


def _ensure_adapters_registered(context: AnalysisContext) -> None:
    """Bulk-register all filesystem adapters the first time we touch storage."""
    mgr = context.storage
    # If we've already registered, the list is non-empty.
    if mgr.filesystems():
        return
    try:
        register_all(mgr)
    except Exception:  # pragma: no cover - defensive
        pass


def _get_layer(context: AnalysisContext, name: str, console: Console) -> DataLayer | None:
    """Fetch ``name`` from the layer registry as a :class:`DataLayer`."""
    from deepview.core.exceptions import LayerError

    try:
        obj = context.layers.get(name)
    except LayerError as e:
        console.print(f"[red]{e}[/red]")
        return None
    if not isinstance(obj, DataLayer):
        console.print(
            f"[red]layer {name!r} is registered but is not a DataLayer "
            f"(got {type(obj).__name__})[/red]"
        )
        return None
    return obj


def _build_spare_layout(kind: str, spare_size: int) -> SpareLayout:
    """Instantiate a :class:`SpareLayout` by preset name."""
    if kind == "onfi":
        return SpareLayout.onfi(spare_size=spare_size)
    if kind == "samsung_klm":
        from deepview.storage.ecc.layouts import samsung_klm

        return samsung_klm(spare_size=spare_size)
    if kind == "toshiba_tc58":
        from deepview.storage.ecc.layouts import toshiba_tc58

        return toshiba_tc58(spare_size=spare_size)
    if kind == "micron_mt29f":
        from deepview.storage.ecc.layouts import micron_mt29f

        return micron_mt29f(spare_size=spare_size)
    raise click.BadParameter(f"unknown --spare-layout: {kind!r}")


def _build_ecc(kind: str) -> Any | None:
    """Lazy-import and instantiate the requested ECC decoder; None if absent."""
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


def _build_ftl(kind: str, geometry: NANDGeometry) -> Any | None:
    """Lazy-import and instantiate the requested FTL translator; None if absent."""
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


@storage.command("info")
@click.option("--layer", "layer_name", required=True, help="Registered layer name to probe")
@click.pass_context
def storage_info(ctx: click.Context, layer_name: str) -> None:
    """Probe a registered layer with every available storage adapter."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    _ensure_adapters_registered(context)

    layer = _get_layer(context, layer_name, console)
    if layer is None:
        raise click.Abort()

    try:
        hits = context.storage.probe(layer)
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    table = Table(title=f"storage probe results for layer {layer_name!r}")
    table.add_column("Adapter", style="cyan")
    if not hits:
        console.print(f"[dim]No adapter recognised {layer_name!r}[/dim]")
        return
    for h in hits:
        table.add_row(h)
    console.print(table)


@storage.command("wrap")
@click.option("--layer", "layer_name", required=True, help="Raw NAND layer to wrap")
@click.option("--out", "out_name", required=True, help="Name to register the wrapped layer as")
@click.option("--ecc", type=click.Choice(_ECC_CHOICES), default=None)
@click.option("--spare-layout", type=click.Choice(_SPARE_CHOICES), default="onfi", show_default=True)
@click.option("--ftl", type=click.Choice(_FTL_CHOICES), default=None)
@click.option("--page-size", type=int, default=2048, show_default=True)
@click.option("--spare-size", type=int, default=64, show_default=True)
@click.option("--pages-per-block", type=int, default=64, show_default=True)
@click.option("--blocks", type=int, default=2048, show_default=True)
@click.pass_context
def storage_wrap(
    ctx: click.Context,
    layer_name: str,
    out_name: str,
    ecc: str | None,
    spare_layout: str,
    ftl: str | None,
    page_size: int,
    spare_size: int,
    pages_per_block: int,
    blocks: int,
) -> None:
    """Compose RawNAND -> (optional ECC) -> (optional FTL) and register the result."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    _ensure_adapters_registered(context)

    layer = _get_layer(context, layer_name, console)
    if layer is None:
        raise click.Abort()

    try:
        layout = _build_spare_layout(spare_layout, spare_size)
    except click.BadParameter as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    geometry = NANDGeometry(
        page_size=page_size,
        spare_size=spare_size,
        pages_per_block=pages_per_block,
        blocks=blocks,
        spare_layout=layout,
    )

    ecc_instance: Any | None = None
    if ecc is not None:
        ecc_instance = _build_ecc(ecc)
        if ecc_instance is None:
            console.print(
                f"[yellow]warning: ecc backend {ecc!r} is not available "
                "(optional dep missing or module not yet shipped) — skipping ECC[/yellow]"
            )

    ftl_instance: Any | None = None
    if ftl is not None:
        ftl_instance = _build_ftl(ftl, geometry)
        if ftl_instance is None:
            console.print(
                f"[yellow]warning: ftl backend {ftl!r} is not available "
                "(optional dep missing or module not yet shipped) — skipping FTL[/yellow]"
            )

    try:
        wrapped = context.storage.wrap_nand(
            layer, geometry, ecc=ecc_instance, ftl=ftl_instance
        )
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]wrap failed: {e}[/red]")
        raise click.Abort() from e

    context.layers.register(out_name, wrapped)
    console.print(
        f"[green]registered[/green] {out_name!r} "
        f"(ecc={ecc or 'none'}, ftl={ftl or 'none'}, layout={spare_layout})"
    )


@storage.command("mount")
@click.option("--layer", "layer_name", required=True)
@click.option("--fs", "fs_type", default=None, help="Filesystem adapter name (auto-probe if omitted)")
@click.pass_context
def storage_mount(
    ctx: click.Context,
    layer_name: str,
    fs_type: str | None,
) -> None:
    """Open a filesystem on a layer and register it as ``<layer>-fs``."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    _ensure_adapters_registered(context)

    layer = _get_layer(context, layer_name, console)
    if layer is None:
        raise click.Abort()

    try:
        fs_obj = context.storage.open_filesystem(layer, fs_type=fs_type)
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    handle_name = f"{layer_name}-fs"
    context.layers.register(handle_name, fs_obj)
    console.print(
        f"[green]mounted[/green] {layer_name!r} as {fs_obj.fs_name or type(fs_obj).__name__} "
        f"-> registered as {handle_name!r}"
    )


@storage.command("list")
@click.pass_context
def storage_list(ctx: click.Context) -> None:
    """Enumerate registered layers, filesystem adapters, FTL translators, and ECC decoders."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    _ensure_adapters_registered(context)

    layers_tab = Table(title="Registered layers")
    layers_tab.add_column("Name", style="cyan")
    layers_tab.add_column("Type")
    for name in context.layers.list_layers():
        obj = context.layers.get(name)
        layers_tab.add_row(name, type(obj).__name__)
    console.print(layers_tab)

    fs_tab = Table(title="Filesystem adapters")
    fs_tab.add_column("Name", style="cyan")
    for name in context.storage.filesystems():
        fs_tab.add_row(name)
    console.print(fs_tab)

    ftl_tab = Table(title="FTL translators")
    ftl_tab.add_column("Name", style="cyan")
    for name in context.storage.ftl_translators():
        ftl_tab.add_row(name)
    console.print(ftl_tab)

    ecc_tab = Table(title="ECC decoders")
    ecc_tab.add_column("Name", style="cyan")
    for name in context.storage.ecc_decoders():
        ecc_tab.add_row(name)
    console.print(ecc_tab)
