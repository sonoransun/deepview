"""Tests for the ``deepview vm`` CLI group.

These tests are hardware-free: ``VMManager`` probes connectors via
``is_available()`` and only registers the ones that import + report readiness.
On a bare CI box none register, so ``vm list`` reports the graceful "no
connector" message; when a connector *is* present its operations are stubbed
through a fake injected directly onto the manager.
"""
from __future__ import annotations

import click
from click.testing import CliRunner
from rich.console import Console

from deepview.cli.commands.vm import vm
from deepview.core.context import AnalysisContext
from deepview.core.exceptions import VMError
from deepview.core.types import SnapshotInfo, VMInfo


def _make_runner_with_context(
    context: AnalysisContext,
) -> tuple[CliRunner, click.Group]:
    """Wrap the ``vm`` group in a root Click group that injects context."""

    @click.group()
    @click.pass_context
    def _root(ctx: click.Context) -> None:
        ctx.ensure_object(dict)
        ctx.obj["context"] = context
        ctx.obj["console"] = Console(record=True, width=200)

    _root.add_command(vm)
    return CliRunner(), _root


class _FakeConnector:
    """Minimal stand-in for a VMConnector used to drive the manager."""

    def __init__(self, vms: list[VMInfo] | None = None) -> None:
        self._vms = vms or []

    def list_vms(self) -> list[VMInfo]:
        return self._vms

    def snapshot(self, vm_id: str, name: str) -> SnapshotInfo:
        return SnapshotInfo(snapshot_id=name, vm_id=vm_id, name=name, has_memory=True)

    def extract_memory(self, vm_id, output):
        return output


def _manager_with_fake(context: AnalysisContext, fake: _FakeConnector) -> None:
    """Force a single fake connector onto the context's VMManager."""
    manager = context.vm
    manager._connectors = {"qemu": fake}


class TestVMList:
    def test_list_no_connector_is_graceful(self) -> None:
        ctx = AnalysisContext.for_testing()
        # Ensure no connectors regardless of host hypervisor state.
        ctx.vm._connectors = {}
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["vm", "list"])
        assert result.exit_code == 0, result.output
        assert "No VM connector available" in result.output

    def test_list_renders_vm_rows(self) -> None:
        ctx = AnalysisContext.for_testing()
        fake = _FakeConnector(
            vms=[
                VMInfo(
                    vm_id="uuid-1",
                    name="webserver",
                    state="running",
                    hypervisor="qemu",
                    memory_mb=2048,
                )
            ]
        )
        _manager_with_fake(ctx, fake)
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["vm", "list"])
        assert result.exit_code == 0, result.output
        assert "webserver" in result.output
        assert "running" in result.output

    def test_list_empty_inventory(self) -> None:
        ctx = AnalysisContext.for_testing()
        _manager_with_fake(ctx, _FakeConnector(vms=[]))
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["vm", "list"])
        assert result.exit_code == 0, result.output
        assert "No virtual machines found" in result.output

    def test_list_connector_error_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()

        class _Boom(_FakeConnector):
            def list_vms(self):  # type: ignore[override]
                raise VMError("hypervisor offline")

        _manager_with_fake(ctx, _Boom())
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(root, ["vm", "list"])
        assert result.exit_code != 0
        assert "hypervisor offline" in result.output


class TestVMSnapshot:
    def test_snapshot_success(self) -> None:
        ctx = AnalysisContext.for_testing()
        _manager_with_fake(ctx, _FakeConnector())
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root, ["vm", "snapshot", "--vm-id", "uuid-1", "--name", "snap1"]
        )
        assert result.exit_code == 0, result.output
        assert "created snapshot" in result.output

    def test_snapshot_no_connector_aborts(self) -> None:
        ctx = AnalysisContext.for_testing()
        ctx.vm._connectors = {}
        runner, root = _make_runner_with_context(ctx)
        result = runner.invoke(
            root, ["vm", "snapshot", "--vm-id", "uuid-1", "--name", "snap1"]
        )
        assert result.exit_code != 0
        # VMManager raises VMError("No VM connector available") when none exist.
        assert "No VM connector available" in result.output


class TestVMExtract:
    def test_extract_success(self, tmp_path) -> None:
        ctx = AnalysisContext.for_testing()
        _manager_with_fake(ctx, _FakeConnector())
        runner, root = _make_runner_with_context(ctx)
        out = tmp_path / "vm.dump"
        result = runner.invoke(
            root,
            ["vm", "extract", "--vm-id", "uuid-1", "--output", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert "extracted" in result.output


class TestVMAnalyze:
    def test_analyze_runs_plugin(self, tmp_path) -> None:
        ctx = AnalysisContext.for_testing()
        _manager_with_fake(ctx, _FakeConnector())

        # Register a trivial plugin so the analyze path runs end-to-end without
        # needing a real memory image or a heavy built-in plugin.
        from deepview.interfaces.plugin import (
            DeepViewPlugin,
            PluginResult,
            Requirement,
        )

        class _StubPlugin(DeepViewPlugin):
            @classmethod
            def get_requirements(cls) -> list[Requirement]:
                return []

            def run(self) -> PluginResult:
                return PluginResult(columns=["k"], rows=[{"k": "v"}])

        ctx.plugins.register("stub", _StubPlugin)

        runner, root = _make_runner_with_context(ctx)
        out = tmp_path / "vm.dump"
        result = runner.invoke(
            root,
            [
                "vm",
                "analyze",
                "--vm-id",
                "uuid-1",
                "--plugin",
                "stub",
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Analysis complete" in result.output

    def test_analyze_unknown_plugin_aborts(self, tmp_path) -> None:
        ctx = AnalysisContext.for_testing()
        _manager_with_fake(ctx, _FakeConnector())
        runner, root = _make_runner_with_context(ctx)
        out = tmp_path / "vm.dump"
        result = runner.invoke(
            root,
            [
                "vm",
                "analyze",
                "--vm-id",
                "uuid-1",
                "--plugin",
                "does-not-exist",
                "--output",
                str(out),
            ],
        )
        assert result.exit_code != 0
        assert "failed" in result.output.lower()
