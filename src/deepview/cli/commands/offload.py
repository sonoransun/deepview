"""Offload CLI group.

Subcommands:

* ``offload status`` — print backend availability / capabilities / in-flight.
* ``offload run`` — submit one job (from a JSON payload file) and dump the result.
* ``offload benchmark`` — run N synthetic PBKDF2 or Argon2id / SHA-512 jobs and
  report wall-clock + throughput.

Every subcommand pulls the engine off the shared
:class:`~deepview.core.context.AnalysisContext` on ``ctx.obj["context"]``;
the engine is constructed lazily on first attribute access, so running
``deepview offload status`` is cheap even when no offload work has
happened yet in the session.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from deepview.core.context import AnalysisContext
from deepview.offload.jobs import make_job


@click.group("offload")
def offload() -> None:
    """Offload engine (thread / process / GPU / remote) — status, run, benchmark."""


@offload.command("status")
@click.pass_context
def offload_status(ctx: click.Context) -> None:
    """Print a table of every registered offload backend."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    status = context.offload.status()
    table = Table(title="Offload backends")
    table.add_column("Name", style="cyan")
    table.add_column("Available")
    table.add_column("Capabilities")
    table.add_column("In-flight", justify="right")

    for name in sorted(status):
        row = status[name]
        avail = "[green]yes[/green]" if row["available"] else "[red]no[/red]"
        caps = ",".join(sorted(row["capabilities"]))  # type: ignore[arg-type]
        table.add_row(name, avail, caps, str(row["in_flight"]))
    console.print(table)


_KIND_TO_CALLABLE = {
    "pbkdf2_sha256": "deepview.offload.kdf:pbkdf2_sha256",
    "argon2id": "deepview.offload.kdf:argon2id",
    "sha512": "deepview.offload.kdf:sha512_iter",
}


@offload.command("run")
@click.option("--kind", required=True, type=click.Choice(sorted(_KIND_TO_CALLABLE)))
@click.option(
    "--json-input",
    "json_input",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a JSON file containing the job payload.",
)
@click.option("--backend", default=None, help="Override the default backend.")
@click.pass_context
def offload_run(
    ctx: click.Context, kind: str, json_input: str, backend: str | None
) -> None:
    """Dispatch one offload job and pretty-print its OffloadResult."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    raw = Path(json_input).read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON payload: {exc}[/red]")
        raise click.Abort() from exc

    # Convert base64-ish hex byte fields: forensic tooling frequently
    # wants to paste ``salt`` / ``password`` as hex rather than escaped
    # JSON unicode. If a str field ends with ``_hex``, decode it in
    # place under the stripped key.
    if isinstance(payload, dict):
        for k in list(payload):
            if isinstance(k, str) and k.endswith("_hex"):
                payload[k[:-4]] = bytes.fromhex(str(payload.pop(k)))

    job = make_job(kind, payload, callable_ref=_KIND_TO_CALLABLE[kind])
    future = context.offload.submit(job, backend=backend)
    result = future.await_result()

    # bytes outputs become hex for display — JSON-safe.
    display_output: object = result.output
    if isinstance(display_output, (bytes, bytearray)):
        display_output = display_output.hex()

    console.print_json(
        data={
            "job_id": result.job_id,
            "ok": result.ok,
            "output": display_output,
            "error": result.error,
            "elapsed_s": result.elapsed_s,
            "backend": result.backend,
        }
    )


@offload.command("benchmark")
@click.option("--kind", required=True, type=click.Choice(sorted(_KIND_TO_CALLABLE)))
@click.option("--iterations", type=int, default=8, show_default=True)
@click.option("--backend", default=None, help="Override the default backend.")
@click.pass_context
def offload_benchmark(
    ctx: click.Context, kind: str, iterations: int, backend: str | None
) -> None:
    """Run *iterations* synthetic KDF jobs and report throughput."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    payloads: list[dict[str, object]] = []
    for _ in range(iterations):
        if kind == "pbkdf2_sha256":
            payloads.append(
                {
                    "password": secrets.token_bytes(16),
                    "salt": secrets.token_bytes(16),
                    "iterations": 100_000,
                    "dklen": 32,
                }
            )
        elif kind == "argon2id":
            payloads.append(
                {
                    "password": secrets.token_bytes(16),
                    "salt": secrets.token_bytes(16),
                    "time_cost": 2,
                    "memory_cost": 64 * 1024,  # KiB
                    "parallelism": max(1, (os.cpu_count() or 1) // 2),
                    "dklen": 32,
                }
            )
        else:  # sha512
            payloads.append(
                {"data": secrets.token_bytes(64), "iterations": 500_000}
            )

    jobs = [make_job(kind, p, callable_ref=_KIND_TO_CALLABLE[kind]) for p in payloads]
    started = time.perf_counter()
    futures = [context.offload.submit(j, backend=backend) for j in jobs]
    results = [f.await_result() for f in futures]
    elapsed = time.perf_counter() - started

    ok_count = sum(1 for r in results if r.ok)
    rate = iterations / elapsed if elapsed > 0 else 0.0
    total_worker_time = sum(r.elapsed_s for r in results)

    table = Table(title=f"offload benchmark — {kind}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("iterations", str(iterations))
    # results[0].backend is authoritative — it's what actually ran.
    backend_used = results[0].backend if results else (backend or "process")
    table.add_row("backend", backend_used)
    table.add_row("elapsed_s (wall)", f"{elapsed:.3f}")
    table.add_row("throughput (jobs/s)", f"{rate:.2f}")
    table.add_row("sum(worker_s)", f"{total_worker_time:.3f}")
    table.add_row("ok / total", f"{ok_count} / {iterations}")
    console.print(table)

    failed = [r for r in results if not r.ok]
    if failed:
        console.print(
            f"[yellow]{len(failed)} job(s) failed; first error:[/yellow] {failed[0].error}"
        )


__all__ = ["offload"]
