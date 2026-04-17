"""Construct a remote acquisition provider without actually connecting.

Smoke-tests the :mod:`deepview.memory.acquisition.remote` wiring:

1. Builds a :class:`RemoteEndpoint` with indirection fields (no inline
   credentials — ``password_env`` names an env var, ``known_hosts`` is a
   file path).
2. Calls :func:`factory.build_remote_provider` for the selected
   transport and prints what would be acquired.

The "dry run" deliberately does **not** call ``provider.acquire`` — that
would open a real SSH / DMA / IPMI session, and the point of this script
is to verify the subsystem can be *wired* cleanly on a core install.

Usage:
    python examples/08_remote_image_dryrun.py --transport ssh \\
        --host 127.0.0.1 --username root \\
        --known-hosts ~/.ssh/known_hosts

Transports: ssh, tcp, udp, agent, lime, dma-tb, dma-pcie, dma-fw,
ipmi, amt
"""
from __future__ import annotations

import argparse
from pathlib import Path

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    RemoteAcquisitionCompletedEvent,
    RemoteAcquisitionProgressEvent,
    RemoteAcquisitionStartedEvent,
)
from deepview.memory.acquisition.remote.base import RemoteEndpoint
from deepview.memory.acquisition.remote.factory import build_remote_provider


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--transport", default="ssh",
                        help="remote transport (default: ssh)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--username", default="root")
    parser.add_argument("--identity-file", type=Path, default=None)
    parser.add_argument("--password-env", default=None,
                        help="name of env var containing password (never inline)")
    parser.add_argument("--known-hosts", type=Path, default=None)
    parser.add_argument("--source", default="/dev/mem",
                        help="remote byte source (extra['source'], ssh only)")
    parser.add_argument("--output", type=Path, default=Path("./remote_memory.raw"),
                        help="local path that *would* receive the image")
    args = parser.parse_args()

    ctx = AnalysisContext.for_testing()

    def on_started(ev: RemoteAcquisitionStartedEvent) -> None:
        print(f"[event] started  endpoint={ev.endpoint} "
              f"transport={ev.transport} output={ev.output}")

    def on_progress(ev: RemoteAcquisitionProgressEvent) -> None:
        print(f"[event] progress endpoint={ev.endpoint} stage={ev.stage} "
              f"bytes_done={ev.bytes_done}")

    def on_completed(ev: RemoteAcquisitionCompletedEvent) -> None:
        print(f"[event] done     endpoint={ev.endpoint} size={ev.size_bytes} "
              f"elapsed={ev.elapsed_s:.3f}s")

    ctx.events.subscribe(RemoteAcquisitionStartedEvent, on_started)
    ctx.events.subscribe(RemoteAcquisitionProgressEvent, on_progress)
    ctx.events.subscribe(RemoteAcquisitionCompletedEvent, on_completed)

    endpoint = RemoteEndpoint(
        host=args.host,
        transport=args.transport,  # type: ignore[arg-type]
        port=args.port,
        username=args.username,
        identity_file=args.identity_file,
        password_env=args.password_env,
        known_hosts=args.known_hosts,
        extra={"source": args.source} if args.transport == "ssh" else {},
    )

    try:
        provider = build_remote_provider(args.transport, endpoint, context=ctx)
    except ValueError as exc:
        print(f"Unknown transport: {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to construct provider: {exc}")
        return 3

    print("Endpoint")
    print(f"  host:             {endpoint.host}")
    print(f"  transport:        {endpoint.transport}")
    print(f"  port:             {endpoint.port}")
    print(f"  username:         {endpoint.username}")
    print(f"  identity_file:    {endpoint.identity_file}")
    print(f"  password_env:     {endpoint.password_env}")
    print(f"  known_hosts:      {endpoint.known_hosts}")
    print(f"  extra:            {dict(endpoint.extra)}")
    print()
    print("Provider")
    print(f"  class:            {type(provider).__name__}")
    print(f"  provider_name:    {provider.provider_name()}")
    print(f"  transport_name:   {provider.transport_name()}")
    try:
        available = provider.is_available()
    except Exception as exc:  # noqa: BLE001
        available = False
        print(f"  is_available:     error — {exc}")
    else:
        print(f"  is_available:     {available}")

    print()
    print("Dry run — would call:")
    print(f"  provider.acquire(target=..., output={args.output}, fmt=RAW)")
    print()
    if not available:
        print("Note: provider reports *not* available on this host — usually the "
              "backing library (paramiko / leechcore / pyghmi / ...) is missing.")
        print("Install via: pip install -e '.[remote_acquisition]'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
