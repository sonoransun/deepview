"""Source-level guards for the Ghidra headless scripts.

These scripts run under Ghidra's Jython interpreter and import ``ghidra.*``, so
they cannot be imported/executed in CI. We guard the known API-correctness bug
(a call to the non-existent ``DecompileResults.depiledFunction``) at the source
level instead.
"""
from __future__ import annotations

from pathlib import Path

import deepview

_SCRIPTS = Path(deepview.__file__).parent / "disassembly" / "scripts" / "ghidra"


def test_decompile_script_uses_valid_decompiler_api():
    src = (_SCRIPTS / "export_decompile.py").read_text()
    # The typo'd method never existed on DecompileResults and always raised.
    assert "depiledFunction" not in src
    # Correct guard + accessor for the pseudo-C output.
    assert "decompileCompleted()" in src
    assert "getDecompiledFunction()" in src
