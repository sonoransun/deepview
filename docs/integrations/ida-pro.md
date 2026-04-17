# IDA Pro

Deep View's disassembly subsystem (`src/deepview/disassembly/`) wraps
Capstone for raw decoding and Ghidra/Hopper for full analysis. It does
not link against IDA directly, but it can emit IDC scripts that import
the same data into an existing IDA database so analysts can pivot from
Deep View findings into their familiar UI.

This guide covers two common handoffs:

1. Exporting a list of `DisassembledInstruction` objects as `MakeComm`
   / `MakeName` statements.
2. Converting a Deep View `ControlFlowGraph` into an IDA function
   annotation via `add_func`, `MakeFunction`, and flow-chart hints.

See [interfaces][iface] and [reference/events][events] for the
underlying types.

[iface]: ../reference/interfaces.md
[events]: ../reference/events.md

## Why IDC instead of IDAPython?

An IDC script runs inside any IDA install (Free, Home, Pro) with no
Python version mismatch. The tradeoff is a smaller API surface — for
deep integrations (type libraries, decompiler overrides) prefer
IDAPython and use the IDC export only as a bootstrap.

!!! note "File extension convention"
    Save scripts as `.idc` so IDA's _File → Script File_ dialog picks
    them up without a reload. `.py` runs through IDAPython but the
    recipes below use IDC-only syntax.

## Exporting `DisassembledInstruction` lists

A `DisassembledInstruction` (from
`deepview.disassembly.interfaces`) has these fields:

```python
@dataclass(slots=True)
class DisassembledInstruction:
    address: int
    mnemonic: str
    op_str: str
    bytes_: bytes
    comment: str | None = None
    xrefs: list[int] = field(default_factory=list)
```

We map each instruction to:

- `MakeComm(addr, "...")` for the `comment` field.
- `MakeName(addr, "...")` if the caller supplied one via `xrefs` tags.
- `AddCodeXref(frm, to, fl_CN)` for each cross-reference.

### `export_idc.py`

```python
"""Render a list of DisassembledInstruction objects as an IDC script."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from deepview.disassembly.interfaces import DisassembledInstruction


def to_idc(instructions: Iterable[DisassembledInstruction]) -> str:
    out = ["#include <idc.idc>", "static main() {"]
    for ins in instructions:
        if ins.comment:
            safe = ins.comment.replace('"', '\\"')
            out.append(f'    MakeComm(0x{ins.address:X}, "{safe}");')
        for xref in ins.xrefs:
            out.append(f"    AddCodeXref(0x{ins.address:X}, 0x{xref:X}, fl_CN);")
    out.append('    Message("Deep View: %d annotations imported\\n");')
    out.append("}")
    return "\n".join(out)


def write(path: Path, instructions: Iterable[DisassembledInstruction]) -> Path:
    path = Path(path)
    path.write_text(to_idc(instructions), encoding="utf-8")
    return path
```

### Usage

```python
from deepview.core.context import AnalysisContext
from deepview.disassembly.engines.capstone_engine import CapstoneEngine

ctx = AnalysisContext.for_testing()
engine = CapstoneEngine(ctx)
insns = engine.disassemble(layer="primary", base=0x400000, size=0x2000)
for ins in insns:
    if ins.mnemonic == "call" and "0x400800" in ins.op_str:
        ins.comment = "deepview: matches rule shell_spawn"

from export_idc import write
write("annotate.idc", insns)
```

In IDA: _File → Script File… → annotate.idc_. IDA appends the comments
at the matching addresses.

## Exporting a Deep View `ControlFlowGraph`

The disassembly engine builds a `ControlFlowGraph` per function (see
`deepview.disassembly.cfg`). To seed IDA's function list:

```python
@dataclass(slots=True)
class ControlFlowGraph:
    entry: int
    blocks: dict[int, BasicBlock]
    edges: list[tuple[int, int]]
    name: str | None = None
```

### `export_cfg_idc.py`

```python
"""Write an IDC script that declares every block's start address as code
and each CFG entry point as a function.

Assumes you have already loaded the binary into IDA at the same base
address Deep View used; otherwise pass --rebase to translate addresses.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from deepview.disassembly.cfg import ControlFlowGraph


def cfg_to_idc(graphs: Iterable[ControlFlowGraph], *, rebase: int = 0) -> str:
    out = ["#include <idc.idc>", "static main() {"]
    for cfg in graphs:
        entry = cfg.entry + rebase
        name = cfg.name or f"dv_{cfg.entry:x}"
        out.append(f"    MakeUnkn(0x{entry:X}, DOUNK_EXPAND);")
        out.append(f"    MakeCode(0x{entry:X});")
        out.append(f'    MakeFunction(0x{entry:X}, BADADDR);')
        out.append(f'    MakeNameEx(0x{entry:X}, "{name}", SN_CHECK);')
        for blk in cfg.blocks.values():
            addr = blk.start + rebase
            out.append(f"    MakeCode(0x{addr:X});")
            if blk.comment:
                c = blk.comment.replace('"', '\\"')
                out.append(f'    MakeComm(0x{addr:X}, "{c}");')
        for src, dst in cfg.edges:
            out.append(
                f"    AddCodeXref(0x{src + rebase:X}, 0x{dst + rebase:X}, fl_JN);"
            )
    out.append('    Message("Deep View: CFG import complete\\n");')
    out.append("}")
    return "\n".join(out)


if __name__ == "__main__":
    import argparse, pickle
    ap = argparse.ArgumentParser()
    ap.add_argument("cfg_pickle")
    ap.add_argument("-o", "--output", default="cfg.idc")
    ap.add_argument("--rebase", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()
    with open(args.cfg_pickle, "rb") as fh:
        graphs = pickle.load(fh)
    Path(args.output).write_text(cfg_to_idc(graphs, rebase=args.rebase))
```

### Round-trip example

```python
from deepview.disassembly.cfg import build_cfg

cfgs = [build_cfg(engine, entry=ep) for ep in engine.discover_entry_points()]
import pickle
with open("cfgs.pkl", "wb") as fh:
    pickle.dump(cfgs, fh)
```

Then in your shell:

```bash
python export_cfg_idc.py cfgs.pkl -o cfgs.idc --rebase 0
```

Load `cfgs.idc` from IDA and your analysis is seeded with Deep View's
block boundaries, edges, and comments.

## Handing back IDA annotations

For the reverse direction (IDA → Deep View), dump a database's comments
as JSON via the IDAPython snippet:

```python
import idautils, idc, json
data = [{"ea": ea, "cmt": idc.get_cmt(ea, 0)} for ea in idautils.Heads() if idc.get_cmt(ea, 0)]
json.dump(data, open("ida_cmts.json", "w"))
```

And load them back into a Deep View `DisassembledInstruction` list by
matching on `address`.

!!! warning "Caveats"
    - **Address rebasing.** Deep View reports virtual addresses from the
      analyzed layer; IDA may have rebased the binary. Always pass
      `--rebase` when loader behavior differs.
    - **Thumb / ARM state.** The IDC scripts assume the instruction set
      matches what IDA auto-detected. If Deep View analyzed ARM/Thumb
      with explicit state, emit `SetProcessorType` and `split_sreg_range`
      calls before `MakeCode`.
    - **Schema drift.** `ControlFlowGraph.comment` is new in Deep View
      0.5. Earlier exports silently skip the comment line; regenerate
      with a matching Deep View version.
    - **IDC string escaping.** The snippets above escape double quotes
      only. Backslashes, newlines, and non-ASCII characters should be
      stripped from comments if you plan to round-trip through IDC.
