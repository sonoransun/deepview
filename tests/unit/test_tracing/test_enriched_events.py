"""Tests for enriched tracing event factories and filter push-down."""
from __future__ import annotations

from deepview.core.types import EventCategory, EventSeverity, ProcessContext
from deepview.tracing.events import (
    MonitorEvent,
    bpf_load_event,
    credential_transition_event,
    exec_event,
    file_access_event,
    fork_event,
    memory_map_event,
    module_load_event,
    network_connect_event,
    network_listen_event,
    ptrace_event,
)
from deepview.tracing.filters import FilterExpr, FilterRule, split_for_pushdown
from deepview.tracing.providers.ebpf import EBPFBackend
from deepview.tracing.providers.endpoint_security import EndpointSecurityBackend
from deepview.tracing.providers.etw import ETWBackend


def _proc(pid: int = 1, comm: str = "test") -> ProcessContext:
    return ProcessContext(pid=pid, comm=comm)


class TestEventFactories:
    def test_exec_event_carries_argv(self) -> None:
        ev = exec_event(process=_proc(), argv=["/bin/sh", "-c", "id"])
        assert ev.category is EventCategory.PROCESS_EXEC
        assert ev.args["argv"] == ["/bin/sh", "-c", "id"]
        assert "exec" in ev.tags

    def test_file_access_event(self) -> None:
        ev = file_access_event(process=_proc(), path="/etc/shadow", operation="open")
        assert ev.category is EventCategory.FILE_ACCESS
        assert ev.args["path"] == "/etc/shadow"
        assert "file" in ev.tags

    def test_network_connect_event_has_tuple(self) -> None:
        ev = network_connect_event(
            process=_proc(),
            protocol="tcp",
            src_ip="10.0.0.1",
            src_port=55555,
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        assert ev.args["dst_port"] == 443
        assert "tcp" in ev.tags

    def test_cred_transition_flags_root_as_warning(self) -> None:
        ev = credential_transition_event(
            process=_proc(), old_uid=1000, new_uid=0
        )
        assert ev.severity is EventSeverity.WARNING
        assert ev.args["new_uid"] == 0

    def test_ptrace_event_is_warning(self) -> None:
        ev = ptrace_event(process=_proc(), target_pid=99, request="PTRACE_ATTACH")
        assert ev.severity is EventSeverity.WARNING
        assert "injection_suspect" in ev.tags

    def test_bpf_load_event(self) -> None:
        ev = bpf_load_event(process=_proc(), prog_type="kprobe")
        assert ev.category is EventCategory.BPF_LOAD

    def test_module_load_event(self) -> None:
        ev = module_load_event(process=_proc(), module_name="rootkit", kind="kernel_module")
        assert ev.category is EventCategory.MODULE_LOAD
        assert ev.args["kind"] == "kernel_module"

    def test_memory_map_event(self) -> None:
        ev = memory_map_event(
            process=_proc(), addr=0x1000, length=4096, prot="RWX"
        )
        assert ev.args["prot"] == "RWX"

    def test_fork_and_network_listen(self) -> None:
        f = fork_event(process=_proc(), child_pid=12345)
        assert f.args["child_pid"] == 12345
        lst = network_listen_event(
            process=_proc(), protocol="tcp", bind_ip="0.0.0.0", bind_port=22
        )
        assert lst.args["bind_port"] == 22


class TestFilterPushdown:
    def test_simple_and_tree_pushes_supported_fields(self) -> None:
        expr = FilterExpr(
            "and",
            [
                FilterRule("process.pid", "eq", 1234),
                FilterRule("args.path", "glob", "/etc/*"),
                FilterRule("syscall_nr", "eq", 1),
            ],
        )
        pushed, remaining = split_for_pushdown(expr)
        pushed_fields = {r.field_path for r in pushed}
        assert "process.pid" in pushed_fields
        assert "args.path" in pushed_fields
        assert any(r.field_path == "syscall_nr" for r in remaining)

    def test_or_tree_is_fully_residual(self) -> None:
        expr = FilterExpr(
            "or",
            [
                FilterRule("process.pid", "eq", 1),
                FilterRule("process.pid", "eq", 2),
            ],
        )
        pushed, remaining = split_for_pushdown(expr)
        assert not pushed
        assert len(remaining) == 2

    def test_none_returns_empty(self) -> None:
        pushed, remaining = split_for_pushdown(None)
        assert pushed == [] and remaining == []


class TestBackendAvailability:
    """These are effectively platform-gated smoke tests: each backend must
    import on every platform and report ``is_available`` truthfully.
    """

    def test_ebpf_backend_imports(self) -> None:
        b = EBPFBackend()
        assert b.backend_name == "ebpf"
        assert b.platform == "linux"

    def test_etw_backend_reports_off_windows(self) -> None:
        b = ETWBackend()
        assert b.backend_name == "etw"
        import sys as _sys

        assert b.is_available() == (_sys.platform == "win32")

    def test_endpoint_security_backend(self) -> None:
        b = EndpointSecurityBackend()
        assert b.backend_name == "endpoint_security"
        import sys as _sys

        assert b.is_available() == (_sys.platform == "darwin")


class TestContainerResolver:
    def test_resolver_is_noop_off_linux(self) -> None:
        import sys as _sys

        from deepview.tracing.providers.container import resolve_for_process

        ctx = _proc()
        result = resolve_for_process(ctx)
        if _sys.platform != "linux":
            assert result is ctx

    def test_resolver_gracefully_handles_missing_proc(self) -> None:
        # Even on Linux, pid=0 must not blow up — resolver returns the input.
        from deepview.tracing.providers.container import resolve_for_process

        ctx = ProcessContext(pid=0, comm="swap")
        result = resolve_for_process(ctx)
        assert result.pid == 0
