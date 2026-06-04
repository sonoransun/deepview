"""Application-instrumentation CLI group.

Subcommands:

* ``instrument attach``  — attach Frida to a running PID and optionally inject
  hooks parsed from a JSON file.
* ``instrument spawn``   — spawn a program suspended under Frida and resume it.
* ``instrument patch``   — statically reassemble a binary with embedded
  monitoring (LIEF / Capstone pipeline).
* ``instrument analyze`` — print a binary's structure summary (LIEF only — the
  cheapest path that does not need Frida).

Frida and LIEF are optional, lazily imported deps. When a backend is missing or
unavailable the command prints a clear install hint and raises
:class:`click.Abort` rather than leaking an ``ImportError`` traceback.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
from rich.console import Console
from rich.table import Table

from deepview.core.exceptions import InstrumentationError, ReassemblyError

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

# Escape the ``[instrumentation]`` extra name so Rich renders it literally
# rather than consuming it as a markup style tag.
_FRIDA_HINT = (
    "[yellow]Instrumentation requires Frida. "
    "Install with: pip install 'deepview\\[instrumentation]'[/yellow]"
)
_LIEF_HINT = (
    "[yellow]Binary analysis requires LIEF. "
    "Install with: pip install 'deepview\\[instrumentation]'[/yellow]"
)


@click.group()
def instrument() -> None:
    """Application instrumentation."""


def _load_hooks(path: str, console: Console) -> list[Any]:
    """Parse a JSON hook-definitions file into :class:`HookDefinition`s."""
    from deepview.interfaces.instrumentor import HookDefinition

    raw = json.loads(Path(path).read_text())
    if isinstance(raw, dict):
        raw = raw.get("hooks", [raw])
    if not isinstance(raw, list):
        raise click.BadParameter("hook file must be a JSON list or {'hooks': [...]}")

    hooks: list[HookDefinition] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise click.BadParameter(f"hook entry #{i} is not an object")
        hooks.append(
            HookDefinition(
                hook_id=str(entry.get("hook_id", f"hook_{i}")),
                module=str(entry.get("module", "")),
                function=str(entry.get("function", "")),
                address=entry.get("address"),
                on_enter=entry.get("on_enter"),
                on_leave=entry.get("on_leave"),
                arg_types=list(entry.get("arg_types", [])),
                capture_backtrace=bool(entry.get("capture_backtrace", False)),
                capture_args=bool(entry.get("capture_args", True)),
                capture_retval=bool(entry.get("capture_retval", True)),
                enabled=bool(entry.get("enabled", True)),
            )
        )
    return hooks


@instrument.command()
@click.option("--pid", type=int, required=True, help="Process ID to attach to")
@click.option(
    "--hooks",
    type=click.Path(exists=True),
    default=None,
    help="Hook definitions file (JSON)",
)
@click.pass_context
def attach(ctx: click.Context, pid: int, hooks: str | None) -> None:
    """Attach to a running process."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    console.print(f"[bold]Attaching to PID {pid}...[/bold]")
    try:
        attached_pid = context.instrumentation.attach(pid)
    except (InstrumentationError, ImportError) as e:
        console.print(f"[red]Failed to attach: {e}[/red]")
        console.print(_FRIDA_HINT)
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Failed to attach: {e}[/red]")
        console.print(_FRIDA_HINT)
        raise click.Abort() from e

    console.print(f"[green]attached[/green] to PID {attached_pid}")

    if hooks:
        try:
            for hook in _load_hooks(hooks, console):
                context.instrumentation.add_hook(attached_pid, hook)
                console.print(f"  [dim]hook injected:[/dim] {hook.hook_id}")
        except click.BadParameter as e:
            console.print(f"[red]{e}[/red]")
            raise click.Abort() from e
        except InstrumentationError as e:
            console.print(f"[red]Hook injection failed: {e}[/red]")
            raise click.Abort() from e


@instrument.command()
@click.option(
    "--program", type=click.Path(exists=True), required=True, help="Program to launch"
)
@click.option(
    "--hooks", type=click.Path(exists=True), default=None, help="Hook definitions file"
)
@click.argument("args", nargs=-1)
@click.pass_context
def spawn(
    ctx: click.Context,
    program: str,
    hooks: str | None,
    args: tuple[str, ...],
) -> None:
    """Launch and instrument a program."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    console.print(f"[bold]Spawning: {program} {' '.join(args)}[/bold]")
    try:
        engine = context.instrumentation._get_frida()
        if not engine.is_available():
            raise InstrumentationError("Frida is not installed")
        session = engine.spawn(Path(program), list(args))
    except (InstrumentationError, ImportError) as e:
        console.print(f"[red]Failed to spawn: {e}[/red]")
        console.print(_FRIDA_HINT)
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Failed to spawn: {e}[/red]")
        console.print(_FRIDA_HINT)
        raise click.Abort() from e

    if hooks:
        try:
            for hook in _load_hooks(hooks, console):
                session.inject_hook(hook)
                console.print(f"  [dim]hook injected:[/dim] {hook.hook_id}")
        except click.BadParameter as e:
            console.print(f"[red]{e}[/red]")
            raise click.Abort() from e

    # Resume the spawned (suspended) process now that hooks are installed.
    resume = getattr(session, "resume", None)
    if callable(resume):
        resume()
    console.print(f"[green]spawned and resumed[/green] PID {session.pid}")


@instrument.command()
@click.option("--binary", type=click.Path(exists=True), required=True, help="Binary to patch")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output binary path")
@click.option(
    "--hooks", type=click.Path(exists=True), default=None, help="Hook definitions file"
)
@click.option(
    "--strategy", type=click.Choice(["security", "exports", "all"]), default="security"
)
@click.pass_context
def patch(
    ctx: click.Context,
    binary: str,
    output: str,
    hooks: str | None,
    strategy: str,
) -> None:
    """Static binary patching with monitoring hooks."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    console.print(f"[bold]Patching binary: {binary}[/bold]")
    console.print(f"  Strategy: {strategy}")
    console.print(f"  Output: {output}")
    try:
        out_path = context.instrumentation.reassemble(
            Path(binary), Path(output), strategy
        )
    except (ReassemblyError, InstrumentationError, ImportError) as e:
        console.print(f"[red]Patch failed: {e}[/red]")
        console.print(_LIEF_HINT)
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Patch failed: {e}[/red]")
        console.print(_LIEF_HINT)
        raise click.Abort() from e

    console.print(f"[green]patched[/green] {binary} -> {out_path}")


@instrument.command("analyze")
@click.option("--binary", type=click.Path(exists=True), required=True, help="Binary to analyze")
@click.pass_context
def analyze_binary(ctx: click.Context, binary: str) -> None:
    """Analyze binary structure."""
    context: AnalysisContext = ctx.obj["context"]
    console: Console = ctx.obj["console"]

    console.print(f"[bold]Analyzing binary: {binary}[/bold]")
    try:
        summary = context.instrumentation.analyze_binary(Path(binary))
    except (InstrumentationError, ImportError) as e:
        console.print(f"[red]Analysis failed: {e}[/red]")
        console.print(_LIEF_HINT)
        raise click.Abort() from e
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Analysis failed: {e}[/red]")
        console.print(_LIEF_HINT)
        raise click.Abort() from e

    if summary.get("format", "unknown") == "unknown":
        console.print(
            "[yellow]Could not parse the binary (LIEF missing or unsupported "
            "format).[/yellow]"
        )
        console.print(_LIEF_HINT)
        return

    table = Table(title=f"Binary summary: {binary}")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for key, value in summary.items():
        table.add_row(str(key), str(value))
    console.print(table)
