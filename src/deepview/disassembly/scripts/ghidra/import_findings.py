# Ghidra script: import Deep View detection findings as bookmarks.
# Usage: Run interactively in Ghidra after loading a binary.
#   Tools > Run Script > import_findings.py
# Provide the path to a Deep View JSON findings file when prompted.
# @category DeepView
# @runtime Jython

import json

from ghidra.program.model.listing import BookmarkType  # noqa: F401


def run():
    findings_path = askFile("Select Deep View findings JSON", "Open")  # noqa: F821
    if findings_path is None:
        return

    with open(str(findings_path), "r") as f:
        data = json.load(f)

    program = getCurrentProgram()  # noqa: F821
    bookmark_mgr = program.getBookmarkManager()
    addr_factory = program.getAddressFactory()

    findings = data.get("findings", data.get("detections", []))
    count = 0
    for finding in findings:
        offset = finding.get("offset", finding.get("address", 0))
        if offset == 0:
            continue
        addr = addr_factory.getAddress("0x{:x}".format(offset))
        name = finding.get("name", "DeepView Finding")
        severity = finding.get("severity", "info").upper()
        description = finding.get("description", "")
        technique = finding.get("technique", "")
        comment = "[{}] {} - {}".format(technique, name, description) if technique else "{} - {}".format(name, description)

        bookmark_mgr.setBookmark(addr, "DeepView", severity, comment)
        count += 1

    println("Imported {} Deep View findings as bookmarks.".format(count))  # noqa: F821


run()
