"""Hopper script: import Deep View detection findings as comments/labels.

Run interactively from Hopper's script console.
The script prompts for a Deep View JSON findings file and creates
inline comments at each finding's address.
"""
import json


def main():
    doc = Document.getCurrentDocument()  # noqa: F821 (Hopper API)
    seg = doc.getSegment(0)

    # Prompt for findings file (Hopper provides a file dialog API)
    # When run via CLI, pass the path as an argument.
    import sys
    if len(sys.argv) > 1:
        findings_path = sys.argv[1]
    else:
        print("Usage: deepview_import.py <findings_json_path>")
        return

    with open(findings_path, "r") as f:
        data = json.load(f)

    findings = data.get("findings", data.get("detections", []))
    count = 0
    for finding in findings:
        offset = finding.get("offset", finding.get("address", 0))
        if offset == 0:
            continue
        name = finding.get("name", "DeepView Finding")
        severity = finding.get("severity", "info")
        description = finding.get("description", "")
        technique = finding.get("technique", "")

        comment = "[DeepView:{}] {} - {}".format(
            technique or severity, name, description
        )

        target_seg = doc.getSegmentAtAddress(offset)
        if target_seg:
            target_seg.setInlineCommentAtAddress(offset, comment)
            count += 1

    print("Imported {} Deep View findings as Hopper comments.".format(count))


main()
