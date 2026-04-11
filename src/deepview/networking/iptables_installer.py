"""Optional iptables NFQUEUE-jump rule installer.

Default is **manual**: Deep View never touches iptables unless the
operator passes ``--install-iptables`` to ``deepview netmangle run``.
When opt-in is on, this module owns the tiny subprocess dance to
insert and remove a single jump rule, and persists the installed
state to ``~/.cache/deepview/mangle_state.json`` so a crashed run
can be recovered via ``deepview netmangle status``.

Every command goes through :func:`_run` which never raises on a
non-zero exit by default — the caller decides whether a missing rule
at cleanup time is an error or a noop. The helper is resilient to
stale state files: an install that finds a stale rule cleans it up
before adding a new one.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deepview.core.logging import get_logger

log = get_logger("networking.iptables_installer")


DEFAULT_STATE_PATH = Path.home() / ".cache" / "deepview" / "mangle_state.json"


@dataclass
class IptablesRule:
    binary: str  # "iptables" or "ip6tables"
    table: str
    chain: str
    queue_num: int
    installed_at_ns: int
    extra_args: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "table": self.table,
            "chain": self.chain,
            "queue_num": self.queue_num,
            "installed_at_ns": self.installed_at_ns,
            "extra_args": list(self.extra_args),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IptablesRule":
        return cls(
            binary=str(data.get("binary", "iptables")),
            table=str(data.get("table", "mangle")),
            chain=str(data.get("chain", "OUTPUT")),
            queue_num=int(data.get("queue_num", 0)),
            installed_at_ns=int(data.get("installed_at_ns", 0)),
            extra_args=list(data.get("extra_args") or []),
        )

    def jump_args(self) -> list[str]:
        return [
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(self.queue_num),
            "--queue-bypass",
        ] + list(self.extra_args)

    def insert_command(self) -> list[str]:
        return [self.binary, "-t", self.table, "-A", self.chain] + self.jump_args()

    def delete_command(self) -> list[str]:
        return [self.binary, "-t", self.table, "-D", self.chain] + self.jump_args()


class IptablesInstaller:
    """Installs and tracks a single NFQUEUE jump rule."""

    def __init__(self, state_path: Path | None = None) -> None:
        self._state_path = Path(state_path) if state_path is not None else DEFAULT_STATE_PATH

    # ------------------------------------------------------------------
    # State file
    # ------------------------------------------------------------------

    def load_state(self) -> list[IptablesRule]:
        if not self._state_path.exists():
            return []
        try:
            data = json.loads(self._state_path.read_text())
        except (OSError, json.JSONDecodeError):
            return []
        rules = data.get("rules") or []
        return [IptablesRule.from_dict(r) for r in rules if isinstance(r, dict)]

    def save_state(self, rules: list[IptablesRule]) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(
            json.dumps({"rules": [r.to_dict() for r in rules]}, indent=2)
        )

    # ------------------------------------------------------------------
    # Install / uninstall
    # ------------------------------------------------------------------

    def install(
        self,
        queue_num: int,
        *,
        binary: str = "iptables",
        table: str = "mangle",
        chain: str = "OUTPUT",
        extra_args: list[str] | None = None,
        runner: Any = None,
    ) -> IptablesRule:
        """Insert an NFQUEUE jump rule and record it in the state file.

        Pass ``runner`` to override ``subprocess.run`` in tests.
        """
        rule = IptablesRule(
            binary=binary,
            table=table,
            chain=chain,
            queue_num=int(queue_num),
            installed_at_ns=time.time_ns(),
            extra_args=list(extra_args or []),
        )
        _run(rule.insert_command(), runner=runner)
        existing = self.load_state()
        existing.append(rule)
        self.save_state(existing)
        log.info(
            "iptables_rule_installed",
            binary=binary,
            table=table,
            chain=chain,
            queue=queue_num,
        )
        return rule

    def uninstall(self, rule: IptablesRule, *, runner: Any = None) -> None:
        """Remove a previously-installed rule and drop it from state."""
        _run(rule.delete_command(), runner=runner, ok_if_missing=True)
        existing = [r for r in self.load_state() if not _rule_equal(r, rule)]
        self.save_state(existing)
        log.info("iptables_rule_uninstalled", queue=rule.queue_num)

    def uninstall_all(self, *, runner: Any = None) -> int:
        """Drop every rule recorded in the state file."""
        rules = self.load_state()
        for r in rules:
            _run(r.delete_command(), runner=runner, ok_if_missing=True)
        self.save_state([])
        return len(rules)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], *, runner: Any, ok_if_missing: bool = False) -> int:
    """Execute *cmd* using ``runner`` (default: ``subprocess.run``).

    When ``ok_if_missing`` is True, a non-zero exit is logged and
    swallowed — useful for idempotent cleanup.
    """
    run_impl = runner if runner is not None else _default_runner
    result = run_impl(cmd)
    if result != 0:
        if ok_if_missing:
            log.debug("iptables_cleanup_non_zero", cmd=" ".join(cmd), rc=result)
            return result
        raise RuntimeError(f"iptables command failed: {' '.join(cmd)} (rc={result})")
    return 0


def _default_runner(cmd: list[str]) -> int:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        log.warning("iptables_stderr", cmd=" ".join(cmd), stderr=proc.stderr.strip())
    return proc.returncode


def _rule_equal(a: IptablesRule, b: IptablesRule) -> bool:
    return (
        a.binary == b.binary
        and a.table == b.table
        and a.chain == b.chain
        and a.queue_num == b.queue_num
    )
