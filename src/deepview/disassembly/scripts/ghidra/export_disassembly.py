# Ghidra headless script: export disassembly at an address or function.
# Usage: analyzeHeadless ... -postScript export_disassembly.py <output_path> <target> [count]
# target: hex address (0x...) or function name
# count: number of instructions (0 = entire function)
# @category DeepView
# @runtime Jython

import json

from ghidra.program.model.listing import CodeUnit  # noqa: F401


def resolve_address(program, target):
    """Resolve a target string to an Address object."""
    addr_factory = program.getAddressFactory()
    # Try as hex address
    if target.startswith("0x") or target.startswith("0X"):
        return addr_factory.getAddress(target)
    # Try as function name
    func_mgr = program.getFunctionManager()
    for func in func_mgr.getFunctions(True):
        if func.getName() == target:
            return func.getEntryPoint()
    return None


def run():
    args = getScriptArgs()  # noqa: F821
    output_path = str(args[0])
    target = str(args[1]) if len(args) > 1 else "0x0"
    count = int(args[2]) if len(args) > 2 else 20

    program = getCurrentProgram()  # noqa: F821
    listing = program.getListing()
    addr = resolve_address(program, target)

    if addr is None:
        with open(output_path, "w") as f:
            json.dump({"error": "Could not resolve target: " + target, "instructions": []}, f)
        return

    instructions = []
    # If count == 0, try to disassemble entire function
    if count == 0:
        func_mgr = program.getFunctionManager()
        func = func_mgr.getFunctionContaining(addr)
        if func:
            body = func.getBody()
            insn_iter = listing.getInstructions(body, True)
            while insn_iter.hasNext():
                insn = insn_iter.next()
                instructions.append({
                    "address": insn.getAddress().getOffset(),
                    "mnemonic": insn.getMnemonicString(),
                    "op_str": " ".join(str(insn.getDefaultOperandRepresentation(i)) for i in range(insn.getNumOperands())),
                    "bytes_hex": "".join("{:02x}".format(b & 0xFF) for b in insn.getBytes()),
                    "size": insn.getLength(),
                })
    else:
        insn = listing.getInstructionAt(addr)
        while insn is not None and len(instructions) < count:
            instructions.append({
                "address": insn.getAddress().getOffset(),
                "mnemonic": insn.getMnemonicString(),
                "op_str": " ".join(str(insn.getDefaultOperandRepresentation(i)) for i in range(insn.getNumOperands())),
                "bytes_hex": "".join("{:02x}".format(b & 0xFF) for b in insn.getBytes()),
                "size": insn.getLength(),
            })
            insn = insn.getNext()

    with open(output_path, "w") as f:
        json.dump({"instructions": instructions}, f, indent=2)


run()
