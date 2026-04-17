"""Encrypted-volume unlock CLI group.

Subcommands:

* ``unlock luks IMAGE`` — unlock a single LUKS1/LUKS2 container with a
  master key, keyfile, or passphrase and register the decrypted layer.
* ``unlock auto IMAGE`` — scan every registered :class:`Unlocker` +
  optionally a memory dump for candidate keys.

Writes are explicitly out of scope for this slice. Even when both
``--confirm`` and ``--enable-write`` are passed, the produced
:class:`DecryptedVolumeLayer` is a read-only view. Writing to the
plaintext volume is a dual-use capability (think: on-disk tampering of
an operating system's root volume) that will land in a later slice
after the operational safety framing in ``netmangle.py`` is extended.

This module is intentionally not registered from ``cli/app.py`` by this
slice — the orchestration owner wires it in after reviewing the
dual-use banner below.
"""
from __future__ import annotations

import asyncio
import getpass
import os
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.storage.containers.layer import DecryptedVolumeLayer
    from deepview.storage.containers.unlock import KeySource


_WRITE_WARNING = (
    "[yellow]Decrypted layers produced by `unlock` are read-only. "
    "Writes to encrypted volumes are out of scope for this slice; "
    "passing both --confirm and --enable-write prints this warning "
    "but does not enable any destructive path.[/yellow]"
)


_AUTO_BANNER = (
    "[bold yellow]AUTO-UNLOCK NOTICE[/bold yellow]\n"
    "--memory-dump scans every byte of the provided dump for AES / LUKS / "
    "BitLocker / FileVault master keys. The resulting candidate keys are "
    "tried against every registered container on the target image. This "
    "is a dual-use capability — scope to evidence you are authorized to "
    "examine."
)


def _load_image_layer(path: str) -> object:
    """Load *path* as a raw disk-image :class:`DataLayer`.

    Uses :class:`~deepview.memory.formats.raw.RawMemoryLayer` because it
    is a byte-addressable file layer with no format assumptions — the
    on-disk LUKS header magic is all we need for detection.
    """
    from deepview.memory.formats.raw import RawMemoryLayer

    return RawMemoryLayer(Path(path))


def _resolve_passphrase(
    passphrase_env: str | None,
    *,
    console: Console,
) -> str:
    if passphrase_env:
        env = os.environ.get(passphrase_env)
        if not env:
            console.print(
                f"[red]environment variable {passphrase_env!r} is unset "
                "or empty[/red]"
            )
            raise click.Abort()
        return env
    return getpass.getpass("Passphrase: ")


def _build_key_source(
    *,
    master_key_hex: str | None,
    keyfile: str | None,
    passphrase: str | None,
) -> KeySource:
    """Build a single :class:`KeySource` from the mutually-exclusive flags."""
    from deepview.storage.containers.unlock import (
        Keyfile,
        MasterKey,
        Passphrase,
    )

    if master_key_hex is not None:
        try:
            return MasterKey(key=bytes.fromhex(master_key_hex))
        except ValueError as exc:
            raise click.UsageError(
                f"--master-key-hex must be hex-encoded: {exc}"
            ) from exc
    if keyfile is not None:
        return Keyfile(path=Path(keyfile))
    if passphrase is not None:
        return Passphrase(passphrase=passphrase)
    raise click.UsageError(
        "one of --master-key-hex, --keyfile, or a passphrase is required"
    )


def _render_results(
    console: Console,
    *,
    container: str,
    key_source: str,
    results: list[DecryptedVolumeLayer],
) -> None:
    table = Table(title="Unlock results")
    table.add_column("Container", style="cyan")
    table.add_column("KeySource", style="magenta")
    table.add_column("ProducedLayer")
    if not results:
        table.add_row(container, key_source, "[red]<no match>[/red]")
    else:
        for layer in results:
            table.add_row(container, key_source, layer.metadata.name)
    console.print(table)


# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group("unlock")
def unlock() -> None:
    """Unlock encrypted containers (LUKS / BitLocker / FileVault / VeraCrypt)."""


@unlock.command("luks")
@click.argument("image", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--passphrase-env",
    type=str,
    default=None,
    help="Environment variable holding the passphrase (avoid passing on argv).",
)
@click.option(
    "--keyfile",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a keyfile (hashed with SHA-256 to derive the key).",
)
@click.option(
    "--master-key-hex",
    type=str,
    default=None,
    help="Hex-encoded master key (32 or 64 bytes).",
)
@click.option(
    "--mount",
    "mount_name",
    type=str,
    default=None,
    help="Register the decrypted layer under this name in the context.",
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Confirm the operation (required with --enable-write).",
)
@click.option(
    "--enable-write",
    is_flag=True,
    default=False,
    help="No-op in this slice; decrypted layers are read-only.",
)
@click.option(
    "--offset",
    type=int,
    default=0,
    show_default=True,
    help="Byte offset of the LUKS header inside IMAGE.",
)
@click.option(
    "--register-as",
    "register_as",
    type=str,
    default=None,
    help="Alias for --mount.",
)
@click.pass_context
def unlock_luks(
    ctx: click.Context,
    image: str,
    passphrase_env: str | None,
    keyfile: str | None,
    master_key_hex: str | None,
    mount_name: str | None,
    confirm: bool,
    enable_write: bool,
    offset: int,
    register_as: str | None,
) -> None:
    """Unlock a LUKS1 / LUKS2 container at IMAGE."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    if enable_write:
        console.print(_WRITE_WARNING)
        if not confirm:
            console.print(
                "[red]refusing: --enable-write requires --confirm[/red]"
            )
            raise click.Abort()

    layer = _load_image_layer(image)

    # Decide key source. If none of the three options are set, prompt.
    passphrase: str | None = None
    if master_key_hex is None and keyfile is None:
        passphrase = _resolve_passphrase(passphrase_env, console=console)
    source = _build_key_source(
        master_key_hex=master_key_hex,
        keyfile=keyfile,
        passphrase=passphrase,
    )

    from deepview.storage.containers.luks import LUKSUnlocker

    unlocker = LUKSUnlocker()
    header = unlocker.detect(layer, offset=offset)  # type: ignore[arg-type]
    if header is None:
        console.print(
            f"[red]no LUKS container detected at offset 0x{offset:x}[/red]"
        )
        raise click.Abort()

    console.print(
        f"[green]detected[/green] {header.format} "
        f"cipher={header.cipher} kdf={header.kdf} "
        f"payload_offset=0x{header.data_offset:x}"
    )

    async def _run() -> DecryptedVolumeLayer:
        return await unlocker.unlock(layer, header, source)  # type: ignore[arg-type]

    try:
        decrypted = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]unlock failed: {exc}[/red]")
        raise click.Abort() from exc

    registered_name = mount_name or register_as
    if registered_name:
        context.layers.register(registered_name, decrypted)

    _render_results(
        console,
        container=header.format,
        key_source=type(source).__name__,
        results=[decrypted],
    )
    if registered_name:
        console.print(
            f"[green]registered layer[/green] name={registered_name!r}"
        )


@unlock.command("auto")
@click.argument("image", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--memory-dump",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Memory image to scan for AES/LUKS master-key candidates.",
)
@click.option(
    "--passphrase-list",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Newline-delimited passphrase dictionary.",
)
@click.option(
    "--keyfile",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Single keyfile to try.",
)
@click.option(
    "--try-hidden",
    is_flag=True,
    default=False,
    help="Also probe for hidden VeraCrypt/TrueCrypt volumes.",
)
@click.option(
    "--register-as-prefix",
    "register_as_prefix",
    type=str,
    default=None,
    help="Prefix under which every decrypted layer is registered.",
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Confirm scanning a memory dump for key material.",
)
@click.pass_context
def unlock_auto(
    ctx: click.Context,
    image: str,
    memory_dump: str | None,
    passphrase_list: str | None,
    keyfile: str | None,
    try_hidden: bool,
    register_as_prefix: str | None,
    confirm: bool,
) -> None:
    """Try every registered unlocker against IMAGE."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    # Dual-use banner for the memory-key-scan path.
    if memory_dump is not None:
        console.print(_AUTO_BANNER)
        if not confirm:
            answer = click.confirm(
                "Scan the supplied memory dump for master-key candidates?",
                default=False,
            )
            if not answer:
                console.print("[yellow]aborted by operator[/yellow]")
                return

    passphrases: list[str] = []
    if passphrase_list is not None:
        for line in Path(passphrase_list).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            line = line.rstrip("\r\n")
            if line:
                passphrases.append(line)

    keyfiles = [Path(keyfile)] if keyfile else []

    # Register the target image + optional memory dump so the
    # orchestrator's `_collect_memory_keys` can see them.
    from deepview.memory.formats.raw import RawMemoryLayer

    image_layer = RawMemoryLayer(Path(image))
    context.layers.register("unlock_target_image", image_layer)
    if memory_dump is not None:
        mem_layer = RawMemoryLayer(Path(memory_dump))
        context.layers.register("unlock_memory_dump", mem_layer)

    async def _run() -> list[DecryptedVolumeLayer]:
        return await context.unlocker.auto_unlock(
            image_layer,
            passphrases=passphrases,
            keyfiles=keyfiles,
            scan_keys=memory_dump is not None,
            try_hidden=try_hidden,
        )

    try:
        results = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]auto-unlock failed: {exc}[/red]")
        raise click.Abort() from exc

    if register_as_prefix:
        for i, layer in enumerate(results):
            context.layers.register(
                f"{register_as_prefix}_{i}", layer
            )

    table = Table(title="auto-unlock results")
    table.add_column("#", justify="right")
    table.add_column("Container")
    table.add_column("ProducedLayer")
    for i, layer in enumerate(results):
        table.add_row(str(i), layer.metadata.name, layer.metadata.name)
    if not results:
        table.add_row("-", "-", "[red]<no unlock succeeded>[/red]")
    console.print(table)


_VERACRYPT_BANNER = (
    "[yellow]VeraCrypt/TrueCrypt unlock performs a brute-force trial "
    "decryption against every supported KDF x cascade combination. "
    "Each attempt is a PBKDF2 derivation and takes measurable CPU "
    "time — this is expected.[/yellow]"
)


def _unlock_container(
    ctx: click.Context,
    image: str,
    *,
    truecrypt: bool,
    passphrase_env: str | None,
    master_key_hex: str | None,
    try_hidden: bool,
    pim: int,
    system_enc: bool,
    mount_name: str | None,
    register_as: str | None,
) -> None:
    """Shared body for the veracrypt + truecrypt subcommands below."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    from deepview.storage.containers.veracrypt import (
        TrueCryptUnlocker,
        VeraCryptUnlocker,
    )

    layer = _load_image_layer(image)

    passphrase: str | None = None
    if master_key_hex is None:
        passphrase = _resolve_passphrase(passphrase_env, console=console)
    source = _build_key_source(
        master_key_hex=master_key_hex,
        keyfile=None,
        passphrase=passphrase,
    )

    console.print(_VERACRYPT_BANNER)
    unlocker_cls = TrueCryptUnlocker if truecrypt else VeraCryptUnlocker
    unlocker = unlocker_cls(pim=pim, system_enc=system_enc)
    header = unlocker.detect(layer)  # type: ignore[arg-type]
    if header is None:
        label = "TrueCrypt" if truecrypt else "VeraCrypt"
        console.print(f"[red]no {label} container detected in {image}[/red]")
        raise click.Abort()

    async def _run() -> DecryptedVolumeLayer:
        return await unlocker.unlock(  # type: ignore[arg-type]
            layer, header, source, try_hidden=try_hidden
        )

    try:
        decrypted = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]unlock failed: {exc}[/red]")
        raise click.Abort() from exc

    registered_name = mount_name or register_as
    if registered_name:
        context.layers.register(registered_name, decrypted)

    _render_results(
        console,
        container=header.format,
        key_source=type(source).__name__,
        results=[decrypted],
    )
    if registered_name:
        console.print(
            f"[green]registered layer[/green] name={registered_name!r}"
        )


@unlock.command("veracrypt")
@click.argument("image", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--passphrase-env",
    type=str,
    default=None,
    help="Environment variable holding the passphrase (avoid passing on argv).",
)
@click.option(
    "--master-key-hex",
    type=str,
    default=None,
    help="Hex-encoded 64-byte header key (skips the KDF).",
)
@click.option(
    "--try-hidden",
    is_flag=True,
    default=False,
    help="Attempt the trailing hidden-volume header after the standard one.",
)
@click.option("--pim", type=int, default=0, help="Personal Iterations Multiplier.")
@click.option(
    "--system/--volume",
    "system_enc",
    default=False,
    help="System-encryption iteration table (pre-boot path).",
)
@click.option(
    "--mount",
    "mount_name",
    type=str,
    default=None,
    help="Register the decrypted layer under this name.",
)
@click.option(
    "--register-as",
    "register_as",
    type=str,
    default=None,
    help="Alias for --mount.",
)
@click.pass_context
def unlock_veracrypt(
    ctx: click.Context,
    image: str,
    passphrase_env: str | None,
    master_key_hex: str | None,
    try_hidden: bool,
    pim: int,
    system_enc: bool,
    mount_name: str | None,
    register_as: str | None,
) -> None:
    """Unlock a VeraCrypt (VERA magic) container at IMAGE."""
    _unlock_container(
        ctx,
        image,
        truecrypt=False,
        passphrase_env=passphrase_env,
        master_key_hex=master_key_hex,
        try_hidden=try_hidden,
        pim=pim,
        system_enc=system_enc,
        mount_name=mount_name,
        register_as=register_as,
    )


@unlock.command("truecrypt")
@click.argument("image", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--passphrase-env",
    type=str,
    default=None,
    help="Environment variable holding the passphrase (avoid passing on argv).",
)
@click.option(
    "--master-key-hex",
    type=str,
    default=None,
    help="Hex-encoded 64-byte header key (skips the KDF).",
)
@click.option(
    "--try-hidden",
    is_flag=True,
    default=False,
    help="Attempt the trailing hidden-volume header after the standard one.",
)
@click.option(
    "--system/--volume",
    "system_enc",
    default=False,
    help="System-encryption iteration table (legacy pre-boot path).",
)
@click.option(
    "--mount",
    "mount_name",
    type=str,
    default=None,
    help="Register the decrypted layer under this name.",
)
@click.option(
    "--register-as",
    "register_as",
    type=str,
    default=None,
    help="Alias for --mount.",
)
@click.pass_context
def unlock_truecrypt(
    ctx: click.Context,
    image: str,
    passphrase_env: str | None,
    master_key_hex: str | None,
    try_hidden: bool,
    system_enc: bool,
    mount_name: str | None,
    register_as: str | None,
) -> None:
    """Unlock a TrueCrypt (TRUE magic) container at IMAGE."""
    _unlock_container(
        ctx,
        image,
        truecrypt=True,
        passphrase_env=passphrase_env,
        master_key_hex=master_key_hex,
        try_hidden=try_hidden,
        pim=0,
        system_enc=system_enc,
        mount_name=mount_name,
        register_as=register_as,
    )


__all__ = ["unlock"]
