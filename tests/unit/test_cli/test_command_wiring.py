"""Tests that CLI command groups are wired to their subsystem managers (#1).

These assert real behavior (rule listing, IoC matching, STIX/ATT&CK export) and,
for environment-dependent commands, that the old print-only placeholder text is
gone -- proving the command now invokes its manager rather than printing a stub.
"""
from __future__ import annotations

import json

from click.testing import CliRunner

from deepview.cli.app import main
from deepview.core.logging import setup_logging


def _teardown():
    # Re-configure structlog after CliRunner closes its captured stderr.
    setup_logging("warning")


class TestScanWiring:
    def teardown_method(self):
        _teardown()

    def test_scan_rules_list_shows_builtin(self):
        result = CliRunner().invoke(main, ["scan", "rules", "--list"])
        assert result.exit_code == 0
        assert "credentials" in result.output
        assert "No rule sets configured" not in result.output  # old stub gone

    def test_scan_rules_default_lists(self):
        result = CliRunner().invoke(main, ["scan", "rules"])
        assert result.exit_code == 0
        assert "rule sets" in result.output.lower()

    def test_scan_ioc_matches(self, tmp_path):
        target = tmp_path / "t.bin"
        target.write_bytes(b"pre evil-mutex post")
        ioc = tmp_path / "ioc.json"
        ioc.write_text(
            json.dumps(
                {"indicators": [{"type": "string", "value": "evil-mutex", "severity": "critical"}]}
            )
        )
        result = CliRunner().invoke(
            main, ["scan", "ioc", "-t", str(target), "--ioc-file", str(ioc)]
        )
        assert result.exit_code == 0
        assert "evil-mutex" in result.output
        assert "1 indicator match" in result.output

    def test_scan_ioc_no_match(self, tmp_path):
        target = tmp_path / "t.bin"
        target.write_bytes(b"clean data only")
        ioc = tmp_path / "ioc.json"
        ioc.write_text(
            json.dumps({"indicators": [{"type": "string", "value": "absent", "severity": "info"}]})
        )
        result = CliRunner().invoke(
            main, ["scan", "ioc", "-t", str(target), "--ioc-file", str(ioc)]
        )
        assert result.exit_code == 0
        assert "0 indicator match" in result.output

    def test_scan_bootkit_clean(self, tmp_path):
        sector = bytearray(512)
        sector[0:3] = b"\xEB\x3C\x90"
        sector[0x1FE:0x200] = b"\x55\xAA"
        img = tmp_path / "disk.img"
        img.write_bytes(bytes(sector))
        result = CliRunner().invoke(main, ["scan", "bootkit", "-i", str(img)])
        assert result.exit_code == 0
        assert "No boot-sector anomalies" in result.output

    def test_scan_bootkit_flags_tampered(self, tmp_path):
        img = tmp_path / "disk.img"
        img.write_bytes(bytes(512))  # invalid signature + empty bootstrap
        result = CliRunner().invoke(main, ["scan", "bootkit", "-i", str(img)])
        assert result.exit_code == 0
        assert "T1542.003" in result.output

    def test_scan_yara_no_generic_stub(self, tmp_path):
        target = tmp_path / "t.bin"
        target.write_bytes(b"data")
        rule = tmp_path / "r.yar"
        rule.write_text("rule x { condition: true }")
        result = CliRunner().invoke(
            main, ["scan", "yara", "-t", str(target), "-r", str(rule)]
        )
        # Either a real result (yara installed) or an honest "not installed"
        # message -- never the old generic install-hint-only stub with no attempt.
        assert "yara-python not installed" in result.output or "match" in result.output


class TestReportExportWiring:
    def teardown_method(self):
        _teardown()

    def test_export_stix_writes_valid_bundle(self, tmp_path):
        out = tmp_path / "bundle.json"
        result = CliRunner().invoke(
            main, ["report", "export", "--format", "stix", "-o", str(out)]
        )
        assert result.exit_code == 0
        assert "Export not yet connected" not in result.output  # old stub gone
        bundle = json.loads(out.read_text())
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert isinstance(bundle["objects"], list)

    def test_export_attck_navigator_layer(self):
        result = CliRunner().invoke(main, ["report", "export", "--format", "attck"])
        assert result.exit_code == 0
        assert "enterprise-attack" in result.output

    def test_export_json_ok(self):
        result = CliRunner().invoke(main, ["report", "export", "--format", "json"])
        assert result.exit_code == 0


class TestMemoryVerify:
    def teardown_method(self):
        _teardown()

    def test_verify_matches(self, tmp_path):
        import hashlib

        img = tmp_path / "mem.raw"
        img.write_bytes(b"EVIDENCE")
        digest = hashlib.sha256(b"EVIDENCE").hexdigest()
        result = CliRunner().invoke(
            main, ["memory", "verify", "-i", str(img), "--sha256", digest]
        )
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_verify_mismatch_exits_nonzero(self, tmp_path):
        img = tmp_path / "mem.raw"
        img.write_bytes(b"EVIDENCE")
        result = CliRunner().invoke(
            main, ["memory", "verify", "-i", str(img), "--sha256", "0" * 64]
        )
        assert result.exit_code == 1
        assert "MISMATCH" in result.output

    def test_verify_from_manifest(self, tmp_path):
        import hashlib
        import json

        img = tmp_path / "mem.raw"
        img.write_bytes(b"EVIDENCE")
        digest = hashlib.sha256(b"EVIDENCE").hexdigest()
        manifest = tmp_path / "mem.raw.manifest.json"
        manifest.write_text(
            json.dumps(
                {"artifacts": [{"path": str(img), "digest": digest, "algorithm": "sha256"}]}
            )
        )
        result = CliRunner().invoke(
            main, ["memory", "verify", "-i", str(img), "--manifest", str(manifest)]
        )
        assert result.exit_code == 0
        assert "OK" in result.output


class TestDoctorHonesty:
    def teardown_method(self):
        _teardown()

    def test_doctor_lists_unimplemented_capabilities(self):
        result = CliRunner().invoke(main, ["doctor"])
        assert result.exit_code == 0
        assert "NOT implemented" in result.output
        # Points the investigator at what IS available so a clean result isn't
        # mistaken for "no threats".
        assert "scan bootkit" in result.output


class TestManagerWiringReplacesStubs:
    """Environment-dependent commands: assert the old placeholder text is gone."""

    def teardown_method(self):
        _teardown()

    def test_memory_acquire_no_placeholder(self, tmp_path):
        result = CliRunner().invoke(
            main, ["memory", "acquire", "-o", str(tmp_path / "m.raw")]
        )
        assert "Acquisition requires platform-specific tools" not in result.output

    def test_vm_list_no_placeholder(self):
        result = CliRunner().invoke(main, ["vm", "list"])
        assert "VM introspection requires a hypervisor" not in result.output

    def test_instrument_analyze_no_frida_stub(self, tmp_path):
        binary = tmp_path / "b.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        result = CliRunner().invoke(main, ["instrument", "analyze", "--binary", str(binary)])
        # analyze is read-only and degrades gracefully without lief; it must not
        # emit the old blanket "requires Frida" stub.
        assert "Instrumentation requires Frida" not in result.output
