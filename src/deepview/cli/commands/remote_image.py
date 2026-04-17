"""``deepview remote-image`` — remote memory acquisition command group.

Every subcommand is a dual-use capability and gated by a common
authorization/banner/delay pattern. The :func:`_authorize_and_banner`
helper enforces:

- ``--confirm`` must be supplied.
- ``--authorization-statement=<file-or-env>`` must resolve to a
  non-empty string (either an env-var lookup via ``env:NAME`` or a
  filesystem path).
- A warning banner + 5-second delay is printed before *any* network
  traffic. ``^C`` during the delay aborts cleanly.
- ``--dry-run`` short-circuits before the banner delay finishes and
  prints the planned operation.

DMA transports add ``--enable-dma`` + root check. Any transport whose
``require_tls`` defaults to True but has neither CA nor known-hosts
material aborts rather than silently downgrading.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import click
from rich.console import Console

from deepview.core.context import AnalysisContext
from deepview.core.logging import get_logger
from deepview.core.types import AcquisitionTarget, DumpFormat
from deepview.memory.acquisition.remote.base import (
    AuthorizationError,
    RemoteEndpoint,
)
from deepview.memory.acquisition.remote.factory import build_remote_provider

log = get_logger("cli.remote_image")


# ---------------------------------------------------------------------------
# Authorization-statement resolution
# ---------------------------------------------------------------------------


def _resolve_authorization_statement(raw: str | None) -> tuple[str, str]:
    """Return ``(source_label, non_empty_text)`` or raise AuthorizationError.

    Supports three forms:

    * ``env:NAME``           — read environment variable ``NAME``.
    * ``file:/path`` / ``/path`` — read the file.
    * Otherwise treat the raw value as the literal statement (last resort;
      still must be non-empty).
    """
    if raw is None or raw.strip() == "":
        raise AuthorizationError("--authorization-statement is required and must be non-empty")

    if raw.startswith("env:"):
        name = raw[4:]
        val = os.environ.get(name, "")
        if not val.strip():
            raise AuthorizationError(
                f"--authorization-statement env:{name} resolved to empty/unset"
            )
        return (f"env:{name}", val.strip())

    if raw.startswith("file:"):
        path = Path(raw[5:])
    elif "/" in raw or raw.endswith(".txt") or Path(raw).exists():
        path = Path(raw)
    else:
        # Literal statement path — must itself be non-empty.
        return ("inline", raw.strip())

    if not path.exists():
        raise AuthorizationError(f"--authorization-statement file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise AuthorizationError(f"--authorization-statement file is empty: {path}")
    return (f"file:{path}", text)


def _authorize_and_banner(
    console: Console,
    *,
    confirm: bool,
    authorization_statement: str | None,
    host: str,
    transport_label: str,
    dry_run: bool,
) -> None:
    """Enforce the authorization gate and print the pre-traffic banner.

    Raises :class:`click.UsageError` (not ``Abort``) when ``--confirm``
    was omitted so Click surfaces the missing-flag semantics cleanly.
    """
    if not confirm:
        raise click.UsageError(
            "--confirm is required for dual-use remote acquisition commands"
        )
    try:
        source_label, _ = _resolve_authorization_statement(authorization_statement)
    except AuthorizationError as e:
        raise click.UsageError(str(e)) from e

    banner = (
        "WARNING: Remote memory acquisition is a dual-use capability. You have attested\n"
        f"authorization via {source_label}. Proceeding against {host} via {transport_label}\n"
        "in 5 seconds. Press ^C to abort."
    )
    console.print(f"[yellow]{banner}[/yellow]")
    if dry_run:
        console.print("[cyan]--dry-run set; no network traffic will occur.[/cyan]")
        return
    try:
        time.sleep(5)
    except KeyboardInterrupt as e:
        raise click.Abort() from e


# ---------------------------------------------------------------------------
# Common click options
# ---------------------------------------------------------------------------


def _common_options(func):  # type: ignore[no-untyped-def]
    """Decorator that stacks the shared options onto every subcommand."""
    func = click.option("--host", required=True, help="Target host or IP")(func)
    func = click.option("--port", type=int, default=None)(func)
    func = click.option("--username", default=None)(func)
    func = click.option(
        "--identity-file", type=click.Path(dir_okay=False), default=None,
        help="SSH private key path",
    )(func)
    func = click.option(
        "--known-hosts", type=click.Path(dir_okay=False), default=None,
        help="SSH known_hosts path (required for ssh)",
    )(func)
    func = click.option(
        "--tls-ca", type=click.Path(dir_okay=False), default=None,
        help="TLS CA bundle (required for agent unless --no-require-tls)",
    )(func)
    func = click.option(
        "--password-env", default=None,
        help="Environment variable name holding the password (never inline)",
    )(func)
    func = click.option(
        "--output", "-o", type=click.Path(dir_okay=False), required=True,
        help="Local output path",
    )(func)
    func = click.option(
        "--format", "fmt", type=click.Choice([f.value for f in DumpFormat]),
        default=DumpFormat.RAW.value,
    )(func)
    func = click.option(
        "--source", default=None,
        help="Remote source path (e.g. /dev/mem, /proc/kcore)",
    )(func)
    func = click.option("--confirm", is_flag=True, default=False)(func)
    func = click.option(
        "--authorization-statement", "authorization_statement", default=None,
        help="env:NAME, file:/path, or an inline non-empty statement",
    )(func)
    func = click.option("--dry-run", is_flag=True, default=False)(func)
    func = click.option(
        "--require-tls/--no-require-tls", default=True,
        help="Abort if TLS verification material is missing",
    )(func)
    return func


def _endpoint_from_opts(
    transport: str,
    *,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    require_tls: bool,
    source: str | None,
) -> RemoteEndpoint:
    extra: dict[str, str] = {}
    if source is not None:
        extra["source"] = source
    return RemoteEndpoint(
        host=host,
        transport=transport,  # type: ignore[arg-type]
        port=port,
        username=username,
        identity_file=Path(identity_file) if identity_file else None,
        password_env=password_env,
        known_hosts=Path(known_hosts) if known_hosts else None,
        tls_ca=Path(tls_ca) if tls_ca else None,
        require_tls=require_tls,
        extra=extra,
    )


def _run_provider(
    ctx: click.Context,
    *,
    transport_factory_key: str,
    transport_label: str,
    endpoint: RemoteEndpoint,
    output: str,
    fmt: str,
    dry_run: bool,
) -> None:
    """Build the provider and run ``acquire`` unless in dry-run mode."""
    console: Console = ctx.obj["console"]
    context: AnalysisContext = ctx.obj["context"]
    if dry_run:
        console.print(
            f"[cyan]plan:[/cyan] transport={transport_label} host={endpoint.host} "
            f"port={endpoint.port} output={output} format={fmt}"
        )
        return
    provider = build_remote_provider(transport_factory_key, endpoint, context=context)
    target = AcquisitionTarget(hostname=endpoint.host)
    result = provider.acquire(target, Path(output), DumpFormat(fmt))
    console.print(
        f"[green]done[/green]: output={result.output_path} size={result.size_bytes} "
        f"format={result.format.value} elapsed={result.duration_seconds:.2f}s"
    )


def _check_tls_material(
    *,
    require_tls: bool,
    tls_ca: str | None,
    known_hosts: str | None,
    transport: str,
) -> None:
    """Abort if ``require_tls`` but no CA / known-hosts material is configured."""
    if not require_tls:
        return
    if transport == "ssh":
        if not known_hosts:
            raise click.UsageError(
                "ssh transport with --require-tls needs --known-hosts "
                "(pass --no-require-tls only if you understand the risk)"
            )
    elif transport == "agent":
        if not tls_ca:
            raise click.UsageError(
                "agent transport with --require-tls needs --tls-ca "
                "(pass --no-require-tls only if you understand the risk)"
            )


# ---------------------------------------------------------------------------
# Group + subcommands
# ---------------------------------------------------------------------------


@click.group("remote-image")
def remote_image() -> None:
    """Remote memory acquisition (SSH/DMA/IPMI/AMT/agent/TCP)."""


@remote_image.command("ssh")
@_common_options
@click.pass_context
def remote_ssh(
    ctx: click.Context,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    output: str,
    fmt: str,
    source: str | None,
    confirm: bool,
    authorization_statement: str | None,
    dry_run: bool,
    require_tls: bool,
) -> None:
    """Acquire via ``ssh host 'sudo dd if=/dev/mem bs=1M'``."""
    console: Console = ctx.obj["console"]
    _authorize_and_banner(
        console,
        confirm=confirm,
        authorization_statement=authorization_statement,
        host=host,
        transport_label="ssh-dd",
        dry_run=dry_run,
    )
    _check_tls_material(
        require_tls=require_tls, tls_ca=tls_ca, known_hosts=known_hosts, transport="ssh"
    )
    endpoint = _endpoint_from_opts(
        "ssh",
        host=host, port=port, username=username,
        identity_file=identity_file, known_hosts=known_hosts,
        tls_ca=tls_ca, password_env=password_env,
        require_tls=require_tls, source=source,
    )
    _run_provider(
        ctx,
        transport_factory_key="ssh", transport_label="ssh-dd",
        endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
    )


@remote_image.command("tcp")
@_common_options
@click.pass_context
def remote_tcp(
    ctx: click.Context,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    output: str,
    fmt: str,
    source: str | None,
    confirm: bool,
    authorization_statement: str | None,
    dry_run: bool,
    require_tls: bool,
) -> None:
    """Bind a TCP listener and accept one external streamer."""
    console: Console = ctx.obj["console"]
    _authorize_and_banner(
        console,
        confirm=confirm,
        authorization_statement=authorization_statement,
        host=host,
        transport_label="tcp-stream",
        dry_run=dry_run,
    )
    endpoint = _endpoint_from_opts(
        "tcp",
        host=host, port=port, username=username,
        identity_file=identity_file, known_hosts=known_hosts,
        tls_ca=tls_ca, password_env=password_env,
        require_tls=require_tls, source=source,
    )
    _run_provider(
        ctx,
        transport_factory_key="tcp", transport_label="tcp-stream",
        endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
    )


@remote_image.command("agent")
@_common_options
@click.pass_context
def remote_agent(
    ctx: click.Context,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    output: str,
    fmt: str,
    source: str | None,
    confirm: bool,
    authorization_statement: str | None,
    dry_run: bool,
    require_tls: bool,
) -> None:
    """Pull memory from a pre-deployed ``deepview-agent``."""
    console: Console = ctx.obj["console"]
    _authorize_and_banner(
        console,
        confirm=confirm,
        authorization_statement=authorization_statement,
        host=host,
        transport_label="network-agent",
        dry_run=dry_run,
    )
    _check_tls_material(
        require_tls=require_tls, tls_ca=tls_ca, known_hosts=known_hosts, transport="agent"
    )
    endpoint = _endpoint_from_opts(
        "grpc",
        host=host, port=port, username=username,
        identity_file=identity_file, known_hosts=known_hosts,
        tls_ca=tls_ca, password_env=password_env,
        require_tls=require_tls, source=source,
    )
    _run_provider(
        ctx,
        transport_factory_key="agent", transport_label="network-agent",
        endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
    )


@remote_image.command("lime")
@_common_options
@click.pass_context
def remote_lime(
    ctx: click.Context,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    output: str,
    fmt: str,
    source: str | None,
    confirm: bool,
    authorization_statement: str | None,
    dry_run: bool,
    require_tls: bool,
) -> None:
    """Remote LiME acquisition (implemented by slice 20)."""
    console: Console = ctx.obj["console"]
    _authorize_and_banner(
        console,
        confirm=confirm,
        authorization_statement=authorization_statement,
        host=host,
        transport_label="lime-remote",
        dry_run=dry_run,
    )
    endpoint = _endpoint_from_opts(
        "ssh",
        host=host, port=port, username=username,
        identity_file=identity_file, known_hosts=known_hosts,
        tls_ca=tls_ca, password_env=password_env,
        require_tls=require_tls, source=source,
    )
    _run_provider(
        ctx,
        transport_factory_key="lime", transport_label="lime-remote",
        endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
    )


def _dma_preflight(
    console: Console,
    *,
    enable_dma: bool,
    transport_label: str,
) -> None:
    """Root + --enable-dma gate shared by every DMA subcommand."""
    if not enable_dma:
        raise click.UsageError(
            f"{transport_label} refuses to run without --enable-dma (dual-use opt-in)"
        )
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise click.UsageError(
            f"{transport_label} refuses to run as non-root (DMA requires ROOT)"
        )


def _dma_command(
    name: str,
    transport_key: str,
    transport_label: str,
) -> click.Command:
    """Build a DMA subcommand with the shared options plus ``--enable-dma``."""

    @click.command(name)
    @_common_options
    @click.option("--enable-dma", is_flag=True, default=False,
                  help="Required opt-in for DMA transports (dual-use)")
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        host: str,
        port: int | None,
        username: str | None,
        identity_file: str | None,
        known_hosts: str | None,
        tls_ca: str | None,
        password_env: str | None,
        output: str,
        fmt: str,
        source: str | None,
        confirm: bool,
        authorization_statement: str | None,
        dry_run: bool,
        require_tls: bool,
        enable_dma: bool,
    ) -> None:
        console: Console = ctx.obj["console"]
        _dma_preflight(console, enable_dma=enable_dma, transport_label=transport_label)
        _authorize_and_banner(
            console,
            confirm=confirm,
            authorization_statement=authorization_statement,
            host=host,
            transport_label=transport_label,
            dry_run=dry_run,
        )
        endpoint = _endpoint_from_opts(
            "dma",
            host=host, port=port, username=username,
            identity_file=identity_file, known_hosts=known_hosts,
            tls_ca=tls_ca, password_env=password_env,
            require_tls=require_tls, source=source,
        )
        _run_provider(
            ctx,
            transport_factory_key=transport_key,
            transport_label=transport_label,
            endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
        )

    return _cmd


remote_image.add_command(_dma_command("dma-tb", "dma-tb", "dma-thunderbolt"))
remote_image.add_command(_dma_command("dma-pcie", "dma-pcie", "dma-pcie"))
remote_image.add_command(_dma_command("dma-fw", "dma-fw", "dma-firewire"))


@remote_image.command("ipmi")
@_common_options
@click.pass_context
def remote_ipmi(
    ctx: click.Context,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    output: str,
    fmt: str,
    source: str | None,
    confirm: bool,
    authorization_statement: str | None,
    dry_run: bool,
    require_tls: bool,
) -> None:
    """IPMI out-of-band acquisition (slice 21)."""
    console: Console = ctx.obj["console"]
    _authorize_and_banner(
        console,
        confirm=confirm,
        authorization_statement=authorization_statement,
        host=host,
        transport_label="ipmi",
        dry_run=dry_run,
    )
    endpoint = _endpoint_from_opts(
        "ipmi",
        host=host, port=port, username=username,
        identity_file=identity_file, known_hosts=known_hosts,
        tls_ca=tls_ca, password_env=password_env,
        require_tls=require_tls, source=source,
    )
    _run_provider(
        ctx,
        transport_factory_key="ipmi", transport_label="ipmi",
        endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
    )


@remote_image.command("amt")
@_common_options
@click.pass_context
def remote_amt(
    ctx: click.Context,
    host: str,
    port: int | None,
    username: str | None,
    identity_file: str | None,
    known_hosts: str | None,
    tls_ca: str | None,
    password_env: str | None,
    output: str,
    fmt: str,
    source: str | None,
    confirm: bool,
    authorization_statement: str | None,
    dry_run: bool,
    require_tls: bool,
) -> None:
    """Intel AMT out-of-band acquisition (slice 21)."""
    console: Console = ctx.obj["console"]
    _authorize_and_banner(
        console,
        confirm=confirm,
        authorization_statement=authorization_statement,
        host=host,
        transport_label="intel-amt",
        dry_run=dry_run,
    )
    endpoint = _endpoint_from_opts(
        "amt",
        host=host, port=port, username=username,
        identity_file=identity_file, known_hosts=known_hosts,
        tls_ca=tls_ca, password_env=password_env,
        require_tls=require_tls, source=source,
    )
    _run_provider(
        ctx,
        transport_factory_key="amt", transport_label="intel-amt",
        endpoint=endpoint, output=output, fmt=fmt, dry_run=dry_run,
    )
