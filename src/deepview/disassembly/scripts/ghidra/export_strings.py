# Ghidra headless script: export strings from a binary.
# Usage: analyzeHeadless ... -postScript export_strings.py <output_path> [min_length]
# @category DeepView
# @runtime Jython

import json

from ghidra.program.util import DefinedDataIterator  # noqa: F401


def run():
    args = getScriptArgs()  # noqa: F821
    output_path = str(args[0])
    min_length = int(args[1]) if len(args) > 1 else 4

    program = getCurrentProgram()  # noqa: F821
    strings = []

    for data in DefinedDataIterator.definedStrings(program):
        value = data.getDefaultValueRepresentation()
        # Strip surrounding quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if len(value) >= min_length:
            strings.append({
                "address": data.getAddress().getOffset(),
                "value": value,
                "encoding": str(data.getDataType()),
                "section": "",
            })

    with open(output_path, "w") as f:
        json.dump({"strings": strings}, f, indent=2)


run()
