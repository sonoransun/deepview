"""Append-only, structured audit log of forensic actions.

Provides a court-defensible, machine-parseable record of which command ran
against which evidence, when (UTC), and with what result/hashes -- supporting
chain-of-custody reconstruction and reproducibility.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def default_audit_log(config_dir: Path) -> Path:
    """Default audit log location under the Deep View config directory."""
    return Path(config_dir) / "audit.log"


def audit_event(log_path: Path, action: str, **fields: Any) -> None:
    """Append one JSON audit record. Never raises on logging failure."""
    record = {
        "utc": datetime.now(timezone.utc).isoformat(),
        "action": action,
    }
    record.update(fields)
    try:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError:
        # Auditing must never abort a forensic operation.
        pass
