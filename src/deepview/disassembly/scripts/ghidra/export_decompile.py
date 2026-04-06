# Ghidra headless script: decompile a function to pseudo-C.
# Usage: analyzeHeadless ... -postScript export_decompile.py <output_path> <target>
# @category DeepView
# @runtime Jython

import json

from ghidra.app.decompiler import DecompInterface  # noqa: F401


def resolve_function(program, target):
    """Resolve target to a Function object."""
    func_mgr = program.getFunctionManager()
    addr_factory = program.getAddressFactory()

    if target.startswith("0x") or target.startswith("0X"):
        addr = addr_factory.getAddress(target)
        func = func_mgr.getFunctionContaining(addr)
        if func:
            return func
    # Try by name
    for func in func_mgr.getFunctions(True):
        if func.getName() == target:
            return func
    return None


def run():
    args = getScriptArgs()  # noqa: F821
    output_path = str(args[0])
    target = str(args[1]) if len(args) > 1 else "main"

    program = getCurrentProgram()  # noqa: F821
    func = resolve_function(program, target)

    if func is None:
        with open(output_path, "w") as f:
            json.dump({"error": "Function not found: " + target, "source": ""}, f)
        return

    decomp = DecompInterface()
    decomp.openProgram(program)
    result = decomp.decompileFunction(func, 60, getMonitor())  # noqa: F821

    source = ""
    if result and result.depiledFunction():
        source = result.getDecompiledFunction().getC()

    with open(output_path, "w") as f:
        json.dump({
            "name": func.getName(),
            "address": func.getEntryPoint().getOffset(),
            "source": source,
            "language": "c",
        }, f, indent=2)


run()
