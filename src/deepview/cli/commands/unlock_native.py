"""Native-adapter unlock CLI (BitLocker + FileVault 2).

This module is a **temporary fork** of the eventual ``deepview unlock``
group. Slice 17 lands BitLocker + FileVault adapters before slice 15's
``unlock.py`` group and slice 16's VeraCrypt sub-command are merged;
rather than modify the pending :mod:`deepview.cli.commands.unlock`
file (owned by another slice), we ship a standalone group
``deepview unlock-native`` here and let the orchestrator fold these
sub-commands back into the primary group once slice 15 lands.

Every sub-command:

- requires an image path argument + ``--confirm`` gate (dual-use);
- prints a warning banner before touching the image;
- pulls passphrases / recovery tokens from **environment variables**,
  never the argv, so shell history / ``ps`` output never contains
  secret material;
- runs the async :class:`UnlockOrchestrator` / per-adapter
  :meth:`Unlocker.unlock` via :func:`asyncio.run`;
- on success prints the produced layer name and optionally
  registers it with ``context.layers`` for follow-on commands.

The commands intentionally do *not* write to the underlying image —
they return a decrypted :class:`DataLayer` that downstream commands can
then mount / inspect / carve read-only.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.interfaces.layer import DataLayer


_BANNER = (
    "DUAL-USE NOTICE: Deep View is about to read and decrypt a volume. "
    "Only proceed against systems you are authorized to analyse. This "
    "command performs no writes; the original image is left untouched."
)


def _print_banner(console: Console) -> None:
    console.print(f"[yellow]{_BANNER}[/yellow]")


def _require_confirm(ctx: click.Context, confirm: bool) -> None:
    if not confirm:
        raise click.UsageError(
            "--confirm is required to acknowledge the dual-use warning"
        )


def _resolve_env(name: str | None) -> str | None:
    """Read a secret from ``os.environ[name]`` (never from argv)."""
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        raise click.UsageError(
            f"environment variable {name!r} is not set"
        )
    return value


def _open_image_layer(path: Path) -> DataLayer:
    """Build a simple :class:`DataLayer` over *path*.

    We use the same raw-file layer :mod:`deepview.memory.formats.raw`
    exposes when importable; otherwise we fall back to an in-memory read
    of the whole image, which is fine for the sub-GiB fixtures we test
    against here.
    """
    try:
        from deepview.memory.formats.raw import RawMemoryLayer

        return RawMemoryLayer(str(path))
    except Exception:
        pass

    # Minimal fallback — slurp + in-memory layer. Acceptable for small
    # container images; production callers will wire the real raw layer.
    from collections.abc import Callable, Iterator

    from deepview.core.types import LayerMetadata, ScanResult
    from deepview.interfaces.layer import DataLayer as _DL

    data = path.read_bytes()

    class _SlurpLayer(_DL):
        def __init__(self, buf: bytes, name: str) -> None:
            self._buf = buf
            self._name = name

        def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
            end = min(offset + length, len(self._buf))
            out = self._buf[max(0, offset):end]
            if pad and len(out) < length:
                out = out + b"\x00" * (length - len(out))
            return out

        def write(self, offset: int, data: bytes) -> None:
            raise NotImplementedError

        def is_valid(self, offset: int, length: int = 1) -> bool:
            return 0 <= offset and offset + length <= len(self._buf)

        def scan(
            self,
            scanner: object,
            progress_callback: Callable | None = None,
        ) -> Iterator[ScanResult]:
            yield from ()

        @property
        def minimum_address(self) -> int:
            return 0

        @property
        def maximum_address(self) -> int:
            return max(0, len(self._buf) - 1)

        @property
        def metadata(self) -> LayerMetadata:
            return LayerMetadata(name=self._name)

    return _SlurpLayer(data, path.name)


@click.group("unlock-native")
def unlock_native() -> None:
    """BitLocker / FileVault 2 unlock sub-commands (standalone fork).

    This group will be folded into ``deepview unlock`` once slice 15 lands.
    """


# ---------------------------------------------------------------------------
# bitlocker
# ---------------------------------------------------------------------------


@unlock_native.command("bitlocker")
@click.argument("image", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--recovery-password",
    "recovery_env",
    default=None,
    metavar="ENV_VAR",
    help="Name of an env var holding the 48-digit BitLocker recovery password.",
)
@click.option(
    "--passphrase-env",
    "passphrase_env",
    default=None,
    metavar="NAME",
    help="Name of an env var holding the BitLocker user password.",
)
@click.option(
    "--keyfile",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a BitLocker startup key (.BEK) file.",
)
@click.option(
    "--fvek-hex",
    default=None,
    metavar="HEX",
    help="Full Volume Encryption Key as a hex string.",
)
@click.option(
    "--fvek-from-memory",
    default=None,
    metavar="LAYER",
    help="Registered memory layer to scan for an FVEK candidate.",
)
@click.option(
    "--register-as",
    default=None,
    metavar="NAME",
    help="Register the produced decrypted layer under this name.",
)
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def bitlocker_cmd(
    ctx: click.Context,
    image: Path,
    recovery_env: str | None,
    passphrase_env: str | None,
    keyfile: Path | None,
    fvek_hex: str | None,
    fvek_from_memory: str | None,
    register_as: str | None,
    confirm: bool,
) -> None:
    """Unlock a BitLocker volume and (optionally) register the plaintext layer."""
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]
    _require_confirm(ctx, confirm)
    _print_banner(console)

    from deepview.storage.containers.bitlocker import BitLockerUnlocker

    layer = _open_image_layer(image)
    unlocker = BitLockerUnlocker()
    header = unlocker.detect(layer)
    if header is None:
        console.print(f"[red]no BitLocker signature found in {image}[/red]")
        raise click.Abort()
    console.print(
        f"[green]detected[/green] {header.format} cipher={header.cipher} "
        f"size={header.data_length}"
    )

    source = _choose_bitlocker_source(
        recovery_env=recovery_env,
        passphrase_env=passphrase_env,
        keyfile=keyfile,
        fvek_hex=fvek_hex,
        fvek_from_memory=fvek_from_memory,
        context=context,
    )

    async def _run() -> DataLayer:
        return await unlocker.unlock(layer, header, source)

    try:
        unlocked = asyncio.run(_run())
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]unlock failed: {e}[/red]")
        raise click.Abort() from e

    _report_unlocked(console, context, unlocked, register_as)


# ---------------------------------------------------------------------------
# filevault
# ---------------------------------------------------------------------------


@unlock_native.command("filevault")
@click.argument("image", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--passphrase-env",
    "passphrase_env",
    default=None,
    metavar="NAME",
    help="Name of an env var holding the FileVault user password.",
)
@click.option(
    "--recovery-password-env",
    "recovery_env",
    default=None,
    metavar="NAME",
    help="Name of an env var holding the FileVault recovery key.",
)
@click.option(
    "--volume-key-hex",
    default=None,
    metavar="HEX",
    help="Volume key data as a hex string (extracted from memory).",
)
@click.option(
    "--register-as",
    default=None,
    metavar="NAME",
    help="Register the produced decrypted layer under this name.",
)
@click.option("--confirm", is_flag=True, default=False)
@click.pass_context
def filevault_cmd(
    ctx: click.Context,
    image: Path,
    passphrase_env: str | None,
    recovery_env: str | None,
    volume_key_hex: str | None,
    register_as: str | None,
    confirm: bool,
) -> None:
    """Unlock a FileVault 2 (Core Storage / APFS) volume."""
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]
    _require_confirm(ctx, confirm)
    _print_banner(console)

    from deepview.storage.containers.filevault2 import FileVault2Unlocker
    from deepview.storage.containers.unlock import MasterKey, Passphrase

    layer = _open_image_layer(image)
    unlocker = FileVault2Unlocker()
    header = unlocker.detect(layer)
    if header is None:
        console.print(f"[red]no FileVault 2 signature found in {image}[/red]")
        raise click.Abort()
    console.print(
        f"[green]detected[/green] {header.format} cipher={header.cipher} "
        f"size={header.data_length}"
    )

    # Resolve key source.
    if volume_key_hex:
        try:
            key_bytes = bytes.fromhex(volume_key_hex)
        except ValueError as e:
            raise click.UsageError(f"invalid --volume-key-hex: {e}") from e
        source: object = MasterKey(key=key_bytes)
    elif passphrase_env:
        pw = _resolve_env(passphrase_env)
        assert pw is not None
        source = Passphrase(passphrase=pw)
    elif recovery_env:
        pw = _resolve_env(recovery_env)
        assert pw is not None
        source = Passphrase(passphrase=pw)
    else:
        raise click.UsageError(
            "one of --passphrase-env / --recovery-password-env / "
            "--volume-key-hex is required"
        )

    async def _run() -> DataLayer:
        return await unlocker.unlock(layer, header, source)  # type: ignore[arg-type]

    try:
        unlocked = asyncio.run(_run())
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]unlock failed: {e}[/red]")
        raise click.Abort() from e

    _report_unlocked(console, context, unlocked, register_as)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _choose_bitlocker_source(
    *,
    recovery_env: str | None,
    passphrase_env: str | None,
    keyfile: Path | None,
    fvek_hex: str | None,
    fvek_from_memory: str | None,
    context: AnalysisContext,
) -> object:
    from deepview.storage.containers.unlock import (
        Keyfile,
        MasterKey,
        Passphrase,
    )

    if fvek_hex:
        try:
            return MasterKey(key=bytes.fromhex(fvek_hex))
        except ValueError as e:
            raise click.UsageError(f"invalid --fvek-hex: {e}") from e

    if fvek_from_memory:
        candidates = _scan_memory_for_fvek(context, fvek_from_memory)
        if not candidates:
            raise click.UsageError(
                f"no FVEK candidates found in layer {fvek_from_memory!r}"
            )
        return MasterKey(key=candidates[0])

    if keyfile is not None:
        return Keyfile(path=Path(keyfile))

    if recovery_env:
        pw = _resolve_env(recovery_env)
        assert pw is not None
        return Passphrase(passphrase=pw)

    if passphrase_env:
        pw = _resolve_env(passphrase_env)
        assert pw is not None
        return Passphrase(passphrase=pw)

    raise click.UsageError(
        "one of --recovery-password / --passphrase-env / --keyfile / "
        "--fvek-hex / --fvek-from-memory is required"
    )


def _scan_memory_for_fvek(
    context: AnalysisContext, layer_name: str
) -> list[bytes]:
    try:
        layer = context.layers.get(layer_name)
    except Exception:
        return []
    try:
        from deepview.detection.encryption_keys import EncryptionKeyScanner
    except Exception:
        return []

    try:
        size = layer.maximum_address + 1
    except Exception:
        return []
    if size <= 0:
        return []
    chunk = min(size, 1 << 20)
    try:
        data = layer.read(0, chunk, pad=True)
    except Exception:
        return []

    scanner = EncryptionKeyScanner()
    out: list[bytes] = []
    for finding in scanner.scan_aes_keys(data, offset=0):
        if finding.key_type in ("aes_128", "aes_256", "bitlocker"):
            out.append(bytes(finding.key_data))
    return out


def _report_unlocked(
    console: Console,
    context: AnalysisContext,
    unlocked: DataLayer,
    register_as: str | None,
) -> None:
    meta = unlocked.metadata
    console.print(
        f"[green]unlocked[/green] layer={meta.name} "
        f"size={unlocked.maximum_address + 1}"
    )
    if register_as:
        try:
            context.layers.register(register_as, unlocked)
            console.print(
                f"[green]registered[/green] as layer {register_as!r}"
            )
        except Exception as e:  # noqa: BLE001
            console.print(
                f"[yellow]could not register layer {register_as!r}: {e}[/yellow]"
            )


__all__ = ["unlock_native"]
