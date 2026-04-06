# Ghidra headless script: export cross-references to/from an address.
# Usage: analyzeHeadless ... -postScript export_xrefs.py <output_path> <address> <direction>
# direction: "to" or "from"
# @category DeepView
# @runtime Jython

import json


def run():
    args = getScriptArgs()  # noqa: F821
    output_path = str(args[0])
    target_addr = str(args[1]) if len(args) > 1 else "0x0"
    direction = str(args[2]) if len(args) > 2 else "to"

    program = getCurrentProgram()  # noqa: F821
    addr_factory = program.getAddressFactory()
    ref_mgr = program.getReferenceManager()
    func_mgr = program.getFunctionManager()

    addr = addr_factory.getAddress(target_addr)
    xrefs = []

    if direction == "to":
        for ref in ref_mgr.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            from_func = func_mgr.getFunctionContaining(from_addr)
            xrefs.append({
                "from_address": from_addr.getOffset(),
                "to_address": addr.getOffset(),
                "ref_type": str(ref.getReferenceType()),
                "from_function": from_func.getName() if from_func else "",
            })
    else:
        for ref in ref_mgr.getReferencesFrom(addr):
            to_addr = ref.getToAddress()
            to_func = func_mgr.getFunctionContaining(to_addr)
            xrefs.append({
                "from_address": addr.getOffset(),
                "to_address": to_addr.getOffset(),
                "ref_type": str(ref.getReferenceType()),
                "to_function": to_func.getName() if to_func else "",
            })

    with open(output_path, "w") as f:
        json.dump({"xrefs": xrefs}, f, indent=2)


run()
