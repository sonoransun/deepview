"""Disassembly and reverse-engineering CLI commands."""
from __future__ import annotations

from pathlib import Path

import click

_MAX_ADDRESS = (1 << 64) - 1  # 0xFFFFFFFFFFFFFFFF


def _parse_address(value: str) -> int:
    """Parse a hex or decimal address string with bounds validation."""
    try:
        addr = int(value, 16) if value.startswith("0x") or value.startswith("0X") else int(value)
    except (ValueError, OverflowError) as exc:
        raise click.BadParameter(f"Invalid address '{value}': {exc}") from exc
    if addr < 0 or addr > _MAX_ADDRESS:
        raise click.BadParameter(
            f"Address 0x{addr:x} out of range (must be 0..0x{_MAX_ADDRESS:x})"
        )
    return addr


@click.group()
def disassemble():
    """Disassembly and reverse engineering."""
    pass


@disassemble.command("disasm")
@click.option("--binary", "-b", type=click.Path(exists=True), required=True, help="Binary to disassemble")
@click.option("--address", "-a", type=str, default=None, help="Start address (hex, e.g. 0x1000)")
@click.option("--function", "-f", "func", type=str, default=None, help="Function name")
@click.option("--count", "-n", type=int, default=20, help="Number of instructions")
@click.option("--engine", type=click.Choice(["ghidra", "hopper", "capstone", "auto"]), default="auto")
@click.pass_context
def disasm(ctx, binary, address, func, count, engine):
    """Disassemble instructions at an address or function."""
    from deepview.disassembly.manager import DisassemblyManager
    from rich.table import Table

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    dm = DisassemblyManager(context)

    try:
        session = dm.open(Path(binary), engine)
        if func:
            instructions = session.disassemble_function(func)[:count]
        elif address:
            addr = _parse_address(address)
            instructions = session.disassemble(addr, count)
        else:
            info = session.binary_info
            ep = info.get("entry_point", 0)
            console.print(f"[dim]No address specified, disassembling from entry point 0x{ep:x}[/dim]")
            instructions = session.disassemble(ep, count)

        table = Table(title=f"Disassembly ({dm.get_engine(engine).engine_name()})")
        table.add_column("Address", style="cyan")
        table.add_column("Bytes", style="dim")
        table.add_column("Mnemonic", style="green")
        table.add_column("Operands")
        for insn in instructions:
            table.add_row(
                f"0x{insn['address']:x}",
                insn.get("bytes_hex", ""),
                insn["mnemonic"],
                insn.get("op_str", ""),
            )
        console.print(table)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    finally:
        dm.close_all()


@disassemble.command("decompile")
@click.option("--binary", "-b", type=click.Path(exists=True), required=True, help="Binary to decompile")
@click.option("--function", "-f", "func", type=str, required=True, help="Function name or hex address")
@click.option("--engine", type=click.Choice(["ghidra", "hopper", "auto"]), default="auto")
@click.pass_context
def decompile(ctx, binary, func, engine):
    """Decompile a function to pseudo-C."""
    from deepview.disassembly.manager import DisassemblyManager

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    dm = DisassemblyManager(context)

    try:
        source = dm.decompile(Path(binary), func, engine)
        from rich.syntax import Syntax

        syntax = Syntax(source, "c", theme="monokai", line_numbers=True)
        console.print(syntax)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    finally:
        dm.close_all()


@disassemble.command("functions")
@click.option("--binary", "-b", type=click.Path(exists=True), required=True, help="Binary to analyze")
@click.option("--engine", type=click.Choice(["ghidra", "hopper", "capstone", "auto"]), default="auto")
@click.option("--filter", "name_filter", type=str, default=None, help="Filter by name pattern (glob)")
@click.pass_context
def list_functions(ctx, binary, engine, name_filter):
    """List functions identified in a binary."""
    from deepview.disassembly.manager import DisassemblyManager
    from rich.table import Table
    import fnmatch

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    dm = DisassemblyManager(context)

    try:
        funcs = dm.functions(Path(binary), engine)
        if name_filter:
            funcs = [f for f in funcs if fnmatch.fnmatch(f.get("name", ""), name_filter)]
        table = Table(title=f"Functions ({dm.get_engine(engine).engine_name()}) - {len(funcs)} found")
        table.add_column("Address", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Size", justify="right")
        for f in funcs:
            table.add_row(
                f"0x{f['address']:x}",
                f.get("name", ""),
                str(f.get("size", "")),
            )
        console.print(table)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    finally:
        dm.close_all()


@disassemble.command("xrefs")
@click.option("--binary", "-b", type=click.Path(exists=True), required=True, help="Binary to analyze")
@click.option("--address", "-a", type=str, required=True, help="Target address (hex)")
@click.option("--direction", type=click.Choice(["to", "from", "both"]), default="to")
@click.option("--engine", type=click.Choice(["ghidra", "hopper", "auto"]), default="auto")
@click.pass_context
def xrefs(ctx, binary, address, direction, engine):
    """Show cross-references to/from an address."""
    from deepview.disassembly.manager import DisassemblyManager
    from rich.table import Table

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    dm = DisassemblyManager(context)
    addr = _parse_address(address)

    try:
        results: list[dict] = []
        session = dm.open(Path(binary), engine)
        if direction in ("to", "both"):
            results.extend(session.xrefs_to(addr))
        if direction in ("from", "both"):
            results.extend(session.xrefs_from(addr))

        table = Table(title=f"Cross-References for 0x{addr:x}")
        table.add_column("From", style="cyan")
        table.add_column("To", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("From Function")
        for ref in results:
            table.add_row(
                f"0x{ref['from_address']:x}",
                f"0x{ref['to_address']:x}",
                ref.get("ref_type", ""),
                ref.get("from_function", ""),
            )
        console.print(table)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    finally:
        dm.close_all()


@disassemble.command("cfg")
@click.option("--binary", "-b", type=click.Path(exists=True), required=True, help="Binary to analyze")
@click.option("--function", "-f", "func", type=str, required=True, help="Function name or hex address")
@click.option("--engine", type=click.Choice(["ghidra", "hopper", "auto"]), default="auto")
@click.option("--format", "output_fmt", type=click.Choice(["json", "dot", "table"]), default="table")
@click.pass_context
def cfg_cmd(ctx, binary, func, engine, output_fmt):
    """Display control-flow graph for a function."""
    import json
    from deepview.disassembly.manager import DisassemblyManager
    from rich.table import Table

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    dm = DisassemblyManager(context)

    try:
        graph = dm.cfg(Path(binary), func, engine)
        if output_fmt == "json":
            console.print(json.dumps(graph, indent=2))
        elif output_fmt == "dot":
            # Generate DOT format for Graphviz
            lines = [f'digraph "{graph.get("function_name", func)}" {{']
            for block in graph.get("blocks", []):
                addr = block["address"]
                lines.append(f'  "0x{addr:x}" [label="0x{addr:x} ({block.get("size", 0)} bytes)"];')
                for succ in block.get("successors", []):
                    lines.append(f'  "0x{addr:x}" -> "0x{succ:x}";')
            lines.append("}")
            console.print("\n".join(lines))
        else:
            table = Table(title=f"CFG: {graph.get('function_name', func)}")
            table.add_column("Block", style="cyan")
            table.add_column("Size", justify="right")
            table.add_column("Successors", style="green")
            table.add_column("Predecessors", style="dim")
            for block in graph.get("blocks", []):
                table.add_row(
                    f"0x{block['address']:x}",
                    str(block.get("size", 0)),
                    ", ".join(f"0x{s:x}" for s in block.get("successors", [])),
                    ", ".join(f"0x{p:x}" for p in block.get("predecessors", [])),
                )
            console.print(table)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    finally:
        dm.close_all()


@disassemble.command("strings")
@click.option("--binary", "-b", type=click.Path(exists=True), required=True, help="Binary to analyze")
@click.option("--min-length", type=int, default=4, help="Minimum string length")
@click.option("--engine", type=click.Choice(["ghidra", "hopper", "capstone", "auto"]), default="auto")
@click.pass_context
def strings_cmd(ctx, binary, min_length, engine):
    """Extract strings from a binary."""
    from deepview.disassembly.manager import DisassemblyManager
    from rich.table import Table

    console = ctx.obj["console"]
    context = ctx.obj["context"]
    dm = DisassemblyManager(context)

    try:
        session = dm.open(Path(binary), engine)
        strs = session.strings(min_length)
        table = Table(title=f"Strings ({len(strs)} found)")
        table.add_column("Address", style="cyan")
        table.add_column("Encoding", style="dim")
        table.add_column("Value")
        for s in strs[:500]:  # Cap output
            table.add_row(
                f"0x{s['address']:x}",
                s.get("encoding", ""),
                s.get("value", "")[:80],
            )
        if len(strs) > 500:
            console.print(f"[dim]... and {len(strs) - 500} more (use --output-format json for full list)[/dim]")
        console.print(table)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
    finally:
        dm.close_all()
