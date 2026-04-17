# Ghidra

Deep View ships a first-party Ghidra integration via
[`pyhidra`][pyhidra], which runs Ghidra's JVM in-process and exposes the
decompiler, the function manager, and the analysis pipeline as a Python
API. This guide shows how to drive Ghidra headless from a Deep View
workflow and how to author scripts under
`src/deepview/disassembly/scripts/` that are loaded by the
`GhidraEngine`.

[pyhidra]: https://github.com/dod-cyber-crime-center/pyhidra

Relevant Deep View modules:

- `disassembly/engines/ghidra_engine.py` — the `GhidraEngine`
  implementation of the `Disassembler` interface.
- `disassembly/scripts/` — Python scripts run inside the Ghidra JVM.
- [disassembly interface reference][iface].

[iface]: ../reference/interfaces.md

!!! note "Optional dependency"
    Ghidra integration requires `pip install -e ".[disassembly]"` plus
    a local Ghidra install (≥ 11.0) with the `GHIDRA_INSTALL_DIR`
    environment variable pointing at it. Tests that exercise the engine
    are marked `requires_ghidra`.

## When to use Ghidra (vs Capstone)

| Scenario | Recommended engine |
| -------- | ------------------ |
| Streaming decode of a memory layer | `CapstoneEngine` (stdlib-fast). |
| Cross-reference, symbol resolution, type propagation | `GhidraEngine`. |
| Decompiling a single suspicious function | `GhidraEngine` with the `decompile` script. |
| IDA-compatible export | `CapstoneEngine` + IDC, see [IDA Pro guide](ida-pro.md). |

## Headless enrichment flow

The typical pattern is:

1. Deep View identifies a suspicious function via Capstone-based
   scanning (e.g., rule hits in packed regions).
2. The analyst or an automated plugin runs `GhidraEngine.analyze()` on
   the same binary to produce a decompilation and a fully-resolved
   `ControlFlowGraph`.
3. The enriched graph is merged back into the session via
   `ctx.artifacts.add("decomp", ...)` and can feed downstream
   classifiers.

```python
from deepview.core.context import AnalysisContext
from deepview.disassembly.engines.ghidra_engine import GhidraEngine

ctx = AnalysisContext.create()
engine = GhidraEngine(ctx)
program = engine.open("/samples/malware.bin")
engine.run_script("decompile_all.py", program=program, out_dir="/tmp/decomp")
```

Under the hood, `run_script` locates the file in
`disassembly/scripts/`, copies it into Ghidra's project scripts
directory, and invokes `analyzeHeadless` with `-postScript`.

## Example scripts

### `disassembly/scripts/decompile_all.py`

```python
"""Decompile every function and dump C source next to the binary.

Runs inside Ghidra's JVM — do not import Deep View modules here; the
script talks only to Ghidra's Java API.
"""
# @category DeepView
# @runtime Jython
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = getScriptArgs()[0] if getScriptArgs() else "/tmp/decomp"
os.makedirs(OUT_DIR, exist_ok=True)

iface = DecompInterface()
iface.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for func in currentProgram.getFunctionManager().getFunctions(True):
    res = iface.decompileFunction(func, 60, monitor)
    if res.decompileCompleted():
        code = res.getDecompiledFunction().getC()
        name = func.getName().replace("/", "_")
        with open(os.path.join(OUT_DIR, f"{name}.c"), "w") as fh:
            fh.write(code)
        print(f"wrote {name}.c ({len(code)} bytes)")
    else:
        print(f"skipped {func.getName()}: {res.getErrorMessage()}")
```

### `disassembly/scripts/export_cfg.py`

Dumps Ghidra's function basic-block graph as a JSON file that Deep View
can read back into a `ControlFlowGraph`:

```python
# @category DeepView
# @runtime Jython
import json

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

OUT = getScriptArgs()[0] if getScriptArgs() else "/tmp/cfg.json"
model = BasicBlockModel(currentProgram)
monitor = ConsoleTaskMonitor()

graphs = []
for func in currentProgram.getFunctionManager().getFunctions(True):
    entry = func.getEntryPoint().getOffset()
    blocks, edges = [], []
    blk_iter = model.getCodeBlocksContaining(func.getBody(), monitor)
    while blk_iter.hasNext():
        blk = blk_iter.next()
        start = blk.getFirstStartAddress().getOffset()
        end = blk.getMaxAddress().getOffset()
        blocks.append({"start": start, "end": end})
        dests = blk.getDestinations(monitor)
        while dests.hasNext():
            dst = dests.next()
            edges.append([start, dst.getDestinationAddress().getOffset()])
    graphs.append({
        "name": func.getName(),
        "entry": entry,
        "blocks": blocks,
        "edges": edges,
    })

with open(OUT, "w") as fh:
    json.dump(graphs, fh, indent=2)

print("wrote %d CFGs to %s" % (len(graphs), OUT))
```

On the Deep View side:

```python
import json
from deepview.disassembly.cfg import ControlFlowGraph, BasicBlock

data = json.load(open("/tmp/cfg.json"))
cfgs = [
    ControlFlowGraph(
        entry=g["entry"],
        blocks={b["start"]: BasicBlock(start=b["start"], end=b["end"]) for b in g["blocks"]},
        edges=[(s, d) for s, d in g["edges"]],
        name=g["name"],
    )
    for g in data
]
ctx.artifacts.add("ghidra_cfg", cfgs)
```

## Headless invocation

`GhidraEngine.run_headless()` is a convenience wrapper around
Ghidra's `analyzeHeadless` shell script. In CI where pyhidra is not
available, you can always fall back to the shell:

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    /tmp/projects deepview_proj \
    -import /samples/malware.bin \
    -scriptPath $(pwd)/src/deepview/disassembly/scripts \
    -postScript export_cfg.py /tmp/cfg.json \
    -deleteProject
```

## Marking tests

Tests that require Ghidra must use the `requires_ghidra` marker and be
skipped if `GHIDRA_INSTALL_DIR` is unset. Example:

```python
@pytest.mark.requires_ghidra
def test_export_cfg(tmp_path):
    if "GHIDRA_INSTALL_DIR" not in os.environ:
        pytest.skip("ghidra not installed")
    ...
```

!!! warning "Caveats"
    - **JVM startup cost.** Each `pyhidra` session spins up a JVM —
      budget ~10 seconds of overhead per headless call. Batch multiple
      samples into one project where possible.
    - **Script languages.** Ghidra accepts Jython (Python 2.7-compatible
      syntax) for in-process scripts; do not use f-strings or
      `pathlib.Path` unless you run via pyhidra's Python 3 bridge. The
      scripts above deliberately stick to Jython-safe subset.
    - **Schema drift.** Ghidra's Java API is stable across minor
      versions but basic-block model semantics shifted at 10.3. Pin your
      Ghidra version if you rely on `BasicBlockModel` output layout.
    - **License.** Ghidra is NSA-licensed open source; using it inside a
      commercial Deep View deployment is fine, but redistributing the
      Ghidra install alongside Deep View is not permitted.
