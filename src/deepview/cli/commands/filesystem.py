"""Filesystem CLI group.

Subcommands:

* ``filesystem ls``   — list directory entries from a registered layer.
* ``filesystem cat``  — dump a file's bytes to stdout.
* ``filesystem stat`` — print key/value metadata for a single entry.
* ``filesystem find`` — walk and print entries whose basename matches a pattern.

All commands operate against a registered ``--layer``; the filesystem is
opened on the fly (auto-probed when ``--fs-type AUTO`` is left at default).
"""
from __future__ import annotations

import stat as stat_mod
import sys
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.table import Table

from deepview.core.context import AnalysisContext
from deepview.interfaces.filesystem import FSEntry, Filesystem
from deepview.interfaces.layer import DataLayer
from deepview.storage.filesystems.registry import register_all
from deepview.storage.manager import StorageError


@click.group("filesystem")
def filesystem() -> None:
    """Filesystem inspection over a registered DataLayer."""


def _ensure_adapters_registered(context: AnalysisContext) -> None:
    mgr = context.storage
    if mgr.filesystems():
        return
    try:
        register_all(mgr)
    except Exception:  # pragma: no cover - defensive
        pass


def _resolve_fs_type(value: str | None) -> str | None:
    """Normalise the CLI's ``--fs-type`` into what ``StorageManager`` expects."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("", "auto"):
        return None
    return v


def _get_layer(context: AnalysisContext, name: str, console: Console) -> DataLayer | None:
    from deepview.core.exceptions import LayerError

    try:
        obj = context.layers.get(name)
    except LayerError as e:
        console.print(f"[red]{e}[/red]")
        return None
    # Already-mounted filesystems are registered as themselves; reject those
    # here — a ``filesystem ls --layer foo-fs`` isn't meaningful.
    if isinstance(obj, Filesystem):
        console.print(
            f"[red]layer {name!r} is a mounted Filesystem; "
            "pass the underlying DataLayer instead[/red]"
        )
        return None
    if not isinstance(obj, DataLayer):
        console.print(
            f"[red]layer {name!r} is not a DataLayer (got {type(obj).__name__})[/red]"
        )
        return None
    return obj


def _open(
    context: AnalysisContext, console: Console, layer_name: str, fs_type: str | None, offset: int
) -> Filesystem | None:
    _ensure_adapters_registered(context)
    layer = _get_layer(context, layer_name, console)
    if layer is None:
        return None
    try:
        return context.storage.open_filesystem(
            layer, fs_type=_resolve_fs_type(fs_type), offset=offset
        )
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        return None


def _fmt_mode(mode: int) -> str:
    try:
        return stat_mod.filemode(mode)
    except Exception:
        return f"{mode:06o}"


def _fmt_time(ts: float | None) -> str:
    if ts is None or ts <= 0:
        return "-"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return "-"


@filesystem.command("ls")
@click.option("--layer", "layer_name", required=True)
@click.option("--fs-type", "fs_type", default="auto", show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.option("--path", default="/", show_default=True)
@click.option("--recursive", is_flag=True, default=False)
@click.option("--include-deleted", is_flag=True, default=False)
@click.pass_context
def filesystem_ls(
    ctx: click.Context,
    layer_name: str,
    fs_type: str,
    offset: int,
    path: str,
    recursive: bool,
    include_deleted: bool,
) -> None:
    """List directory entries from a registered layer."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    fs = _open(context, console, layer_name, fs_type, offset)
    if fs is None:
        raise click.Abort()

    table = Table(title=f"{layer_name}:{path}")
    table.add_column("Path", style="cyan", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("Mode")
    table.add_column("MTime")
    table.add_column("Deleted")

    try:
        for entry in fs.list(path, recursive=recursive, include_deleted=include_deleted):
            table.add_row(
                entry.path,
                str(entry.size),
                _fmt_mode(entry.mode),
                _fmt_time(entry.mtime),
                "yes" if entry.is_deleted else "",
            )
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    console.print(table)


@filesystem.command("cat")
@click.option("--layer", "layer_name", required=True)
@click.option("--path", required=True)
@click.option("--fs-type", "fs_type", default="auto", show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.pass_context
def filesystem_cat(
    ctx: click.Context,
    layer_name: str,
    path: str,
    fs_type: str,
    offset: int,
) -> None:
    """Read *path* from the filesystem and write its bytes to stdout."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    fs = _open(context, console, layer_name, fs_type, offset)
    if fs is None:
        raise click.Abort()
    try:
        data = fs.read(path)
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write(data)
        buf.flush()
    else:  # test runners often replace stdout with a text sink
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        sys.stdout.flush()


@filesystem.command("stat")
@click.option("--layer", "layer_name", required=True)
@click.option("--path", required=True)
@click.option("--fs-type", "fs_type", default="auto", show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.pass_context
def filesystem_stat(
    ctx: click.Context,
    layer_name: str,
    path: str,
    fs_type: str,
    offset: int,
) -> None:
    """Print :class:`FSEntry` fields for *path* as a key/value table."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    fs = _open(context, console, layer_name, fs_type, offset)
    if fs is None:
        raise click.Abort()
    try:
        entry = fs.stat(path)
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e

    table = Table(title=f"stat {path}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", overflow="fold")
    rows: list[tuple[str, str]] = [
        ("path", entry.path),
        ("inode", str(entry.inode)),
        ("size", str(entry.size)),
        ("mode", f"{_fmt_mode(entry.mode)} ({entry.mode:06o})"),
        ("uid", str(entry.uid)),
        ("gid", str(entry.gid)),
        ("mtime", _fmt_time(entry.mtime)),
        ("atime", _fmt_time(entry.atime)),
        ("ctime", _fmt_time(entry.ctime)),
        ("btime", _fmt_time(entry.btime) if entry.btime is not None else "-"),
        ("is_dir", str(entry.is_dir)),
        ("is_symlink", str(entry.is_symlink)),
        ("is_deleted", str(entry.is_deleted)),
        ("target", entry.target or "-"),
    ]
    for k, v in rows:
        table.add_row(k, v)
    if entry.extra:
        for k, v in entry.extra.items():
            table.add_row(f"extra.{k}", str(v))
    console.print(table)


@filesystem.command("find")
@click.option("--layer", "layer_name", required=True)
@click.option("--pattern", required=True)
@click.option("--regex", is_flag=True, default=False)
@click.option("--fs-type", "fs_type", default="auto", show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
@click.pass_context
def filesystem_find(
    ctx: click.Context,
    layer_name: str,
    pattern: str,
    regex: bool,
    fs_type: str,
    offset: int,
) -> None:
    """Walk the filesystem and print entries whose basename matches *pattern*."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]
    fs = _open(context, console, layer_name, fs_type, offset)
    if fs is None:
        raise click.Abort()
    table = Table(title=f"find {pattern!r} on {layer_name}")
    table.add_column("Path", style="cyan", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("MTime")
    matches = 0
    try:
        for entry in fs.find(pattern, regex=regex):
            matches += 1
            table.add_row(entry.path, str(entry.size), _fmt_time(entry.mtime))
    except StorageError as e:
        console.print(f"[red]{e}[/red]")
        raise click.Abort() from e
    console.print(table)
    console.print(f"[dim]{matches} match(es)[/dim]")


__all__ = ["filesystem", "FSEntry"]
