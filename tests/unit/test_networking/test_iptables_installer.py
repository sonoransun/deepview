"""IptablesInstaller tests with subprocess mocked out."""
from __future__ import annotations

import json

import pytest

from deepview.networking.iptables_installer import (
    IptablesInstaller,
)


class Recorder:
    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode

    def __call__(self, cmd: list[str]) -> int:
        self.calls.append(list(cmd))
        return self.returncode


class TestInstallUninstall:
    def test_install_runs_iptables_and_records_state(self, tmp_path):
        state = tmp_path / "state.json"
        installer = IptablesInstaller(state_path=state)
        runner = Recorder()
        rule = installer.install(42, runner=runner)
        assert rule.queue_num == 42
        assert runner.calls == [
            ["iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "42", "--queue-bypass"]
        ]
        state_data = json.loads(state.read_text())
        assert len(state_data["rules"]) == 1
        assert state_data["rules"][0]["queue_num"] == 42

    def test_uninstall_removes_rule_and_state(self, tmp_path):
        state = tmp_path / "state.json"
        installer = IptablesInstaller(state_path=state)
        runner = Recorder()
        rule = installer.install(42, runner=runner)
        installer.uninstall(rule, runner=runner)
        state_data = json.loads(state.read_text())
        assert state_data["rules"] == []
        # Two calls: install then uninstall.
        assert len(runner.calls) == 2
        # iptables -t mangle -D OUTPUT ...
        assert runner.calls[1][3] == "-D"

    def test_install_failure_raises(self, tmp_path):
        state = tmp_path / "state.json"
        installer = IptablesInstaller(state_path=state)
        runner = Recorder(returncode=1)
        with pytest.raises(RuntimeError):
            installer.install(42, runner=runner)
        # Nothing recorded if the install failed.
        if state.exists():
            assert json.loads(state.read_text())["rules"] == []

    def test_uninstall_all_walks_state(self, tmp_path):
        state = tmp_path / "state.json"
        installer = IptablesInstaller(state_path=state)
        runner = Recorder()
        installer.install(10, runner=runner)
        installer.install(11, runner=runner)
        installer.install(12, runner=runner)
        removed = installer.uninstall_all(runner=runner)
        assert removed == 3
        assert json.loads(state.read_text())["rules"] == []
