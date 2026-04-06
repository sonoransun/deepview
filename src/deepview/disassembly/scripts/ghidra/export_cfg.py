# Ghidra headless script: export control-flow graph for a function.
# Usage: analyzeHeadless ... -postScript export_cfg.py <output_path> <target>
# @category DeepView
# @runtime Jython

import json

from ghidra.program.model.block import BasicBlockModel  # noqa: F401


def resolve_function(program, target):
    """Resolve target to a Function object."""
    func_mgr = program.getFunctionManager()
    addr_factory = program.getAddressFactory()

    if target.startswith("0x") or target.startswith("0X"):
        addr = addr_factory.getAddress(target)
        func = func_mgr.getFunctionContaining(addr)
        if func:
            return func
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
            json.dump({"error": "Function not found: " + target, "blocks": []}, f)
        return

    model = BasicBlockModel(program)
    monitor = getMonitor()  # noqa: F821
    body = func.getBody()

    blocks = []
    edge_count = 0
    block_iter = model.getCodeBlocksContaining(body, monitor)
    while block_iter.hasNext():
        block = block_iter.next()
        start = block.getMinAddress().getOffset()
        size = block.getNumAddresses()

        successors = []
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            dest_addr = dest.getDestinationAddress()
            if body.contains(dest_addr):
                successors.append(dest_addr.getOffset())
                edge_count += 1

        predecessors = []
        src_iter = block.getSources(monitor)
        while src_iter.hasNext():
            src = src_iter.next()
            src_addr = src.getSourceAddress()
            if body.contains(src_addr):
                predecessors.append(src_addr.getOffset())

        blocks.append({
            "address": start,
            "size": size,
            "successors": successors,
            "predecessors": predecessors,
        })

    with open(output_path, "w") as f:
        json.dump({
            "function_name": func.getName(),
            "function_address": func.getEntryPoint().getOffset(),
            "blocks": blocks,
            "edge_count": edge_count,
        }, f, indent=2)


run()
