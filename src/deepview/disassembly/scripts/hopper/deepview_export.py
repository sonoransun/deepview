"""Hopper script: export analysis results in Deep View JSON format.

Run from Hopper's script console or via headless mode.
Command-line usage: hopper --headless -e <binary> --script deepview_export.py --args <output_path> <command> [args...]

Commands:
  functions                   - Export all functions
  disassemble <addr> <count>  - Disassemble at address
  disassemble_function <name> - Disassemble entire function
  decompile <name>            - Decompile function to pseudo-code
  cfg <name>                  - Export control-flow graph
  strings [min_length]        - Export strings
"""
import json
import sys


def export_functions(doc, output_path):
    """Export all functions from the document."""
    functions = []
    seg_count = doc.getSegmentCount()
    for i in range(seg_count):
        seg = doc.getSegment(i)
        proc_count = seg.getProcedureCount()
        for j in range(proc_count):
            proc = seg.getProcedureAtIndex(j)
            functions.append({
                "name": proc.getName(),
                "address": proc.getEntryPoint(),
                "size": proc.getBasicBlockCount(),  # approximate
            })

    with open(output_path, "w") as f:
        json.dump({"functions": functions}, f, indent=2)


def export_disassemble(doc, output_path, address, count):
    """Disassemble instructions at an address."""
    addr = int(address, 16) if isinstance(address, str) else address
    instructions = []
    seg = doc.getSegmentAtAddress(addr)
    if seg:
        current = addr
        for _ in range(count):
            insn_len = seg.getInstructionLength(current)
            if insn_len == 0:
                break
            instructions.append({
                "address": current,
                "mnemonic": seg.getInstructionString(current),
                "op_str": seg.getOperandString(current, 0),
                "bytes_hex": "",
                "size": insn_len,
            })
            current += insn_len

    with open(output_path, "w") as f:
        json.dump({"instructions": instructions}, f, indent=2)


def export_decompile(doc, output_path, target):
    """Decompile a function to pseudo-code."""
    seg_count = doc.getSegmentCount()
    for i in range(seg_count):
        seg = doc.getSegment(i)
        proc_count = seg.getProcedureCount()
        for j in range(proc_count):
            proc = seg.getProcedureAtIndex(j)
            if proc.getName() == target or hex(proc.getEntryPoint()) == target:
                source = proc.decompile()
                with open(output_path, "w") as f:
                    json.dump({
                        "name": proc.getName(),
                        "address": proc.getEntryPoint(),
                        "source": source,
                        "language": "pseudo-c",
                    }, f, indent=2)
                return

    with open(output_path, "w") as f:
        json.dump({"error": "Function not found: " + target, "source": ""}, f)


def export_strings(doc, output_path, min_length):
    """Export strings from the binary."""
    strings = []
    seg_count = doc.getSegmentCount()
    for i in range(seg_count):
        seg = doc.getSegment(i)
        str_count = seg.getStringCount() if hasattr(seg, "getStringCount") else 0
        for j in range(str_count):
            s = seg.getStringAtIndex(j)
            value = s.getValue() if hasattr(s, "getValue") else str(s)
            if len(value) >= min_length:
                strings.append({
                    "address": s.getAddress() if hasattr(s, "getAddress") else 0,
                    "value": value,
                    "encoding": "utf-8",
                })

    with open(output_path, "w") as f:
        json.dump({"strings": strings}, f, indent=2)


def main():
    args = sys.argv[1:] if len(sys.argv) > 1 else []
    if len(args) < 2:
        print("Usage: deepview_export.py <output_path> <command> [args...]")
        return

    output_path = args[0]
    command = args[1]

    doc = Document.getCurrentDocument()  # noqa: F821 (Hopper API)

    if command == "functions":
        export_functions(doc, output_path)
    elif command == "disassemble":
        address = args[2] if len(args) > 2 else "0x0"
        count = int(args[3]) if len(args) > 3 else 20
        export_disassemble(doc, output_path, address, count)
    elif command == "disassemble_function":
        target = args[2] if len(args) > 2 else "main"
        export_disassemble(doc, output_path, target, 500)
    elif command == "decompile":
        target = args[2] if len(args) > 2 else "main"
        export_decompile(doc, output_path, target)
    elif command == "cfg":
        with open(output_path, "w") as f:
            json.dump({"error": "CFG export not yet implemented for Hopper"}, f)
    elif command == "strings":
        min_len = int(args[2]) if len(args) > 2 else 4
        export_strings(doc, output_path, min_len)
    else:
        with open(output_path, "w") as f:
            json.dump({"error": "Unknown command: " + command}, f)


main()
