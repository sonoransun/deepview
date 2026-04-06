# Ghidra headless script: export all identified functions as JSON.
# Usage: analyzeHeadless ... -postScript export_functions.py <output_path>
# @category DeepView
# @runtime Jython

import json


def run():
    output_path = str(getScriptArgs()[0])  # noqa: F821
    program = getCurrentProgram()  # noqa: F821
    func_mgr = program.getFunctionManager()

    functions = []
    for func in func_mgr.getFunctions(True):
        params = []
        for p in func.getParameters():
            params.append({
                "name": p.getName(),
                "type": str(p.getDataType()),
                "ordinal": p.getOrdinal(),
            })

        functions.append({
            "name": func.getName(),
            "address": func.getEntryPoint().getOffset(),
            "size": func.getBody().getNumAddresses(),
            "calling_convention": str(func.getCallingConventionName()),
            "return_type": str(func.getReturnType()),
            "parameters": params,
        })

    with open(output_path, "w") as f:
        json.dump({"functions": functions}, f, indent=2)


run()
