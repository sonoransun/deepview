"""Tests for the append-only forensic audit log."""
from __future__ import annotations

import json

from deepview.utils.audit import audit_event, default_audit_log


def test_default_audit_log_path(tmp_path):
    assert default_audit_log(tmp_path) == tmp_path / "audit.log"


def test_audit_event_appends_jsonl(tmp_path):
    log = tmp_path / "sub" / "audit.log"  # parent created on demand
    audit_event(log, "memory.acquire", output="a.raw", digest="d1")
    audit_event(log, "memory.verify", image="a.raw", matched=True)

    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    assert rec0["action"] == "memory.acquire"
    assert rec0["output"] == "a.raw"
    assert "utc" in rec0
    rec1 = json.loads(lines[1])
    assert rec1["action"] == "memory.verify"
    assert rec1["matched"] is True


def test_audit_event_never_raises_on_bad_path(tmp_path):
    # A path whose parent is a file (not a dir) cannot be created; must not raise.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    audit_event(blocker / "nested" / "audit.log", "noop")
