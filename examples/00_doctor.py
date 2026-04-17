"""Programmatic equivalent of ``deepview doctor``.

Constructs an :class:`~deepview.core.context.AnalysisContext` for testing,
prints the detected platform info, and reports which optional extras are
available on this machine. All optional dependencies are probed lazily so
the script runs on a bare core install without any of them.

Usage:
    python examples/00_doctor.py
    python examples/00_doctor.py --json
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import asdict, dataclass

from deepview.core.context import AnalysisContext


@dataclass(frozen=True)
class ExtraStatus:
    extra: str
    module: str
    installed: bool
    version: str = ""
    error: str = ""


EXTRAS: tuple[tuple[str, str], ...] = (
    ("memory", "volatility3"),
    ("memory", "memprocfs"),
    ("storage", "pytsk3"),
    ("storage", "libbfio"),
    ("containers", "cryptography"),
    ("containers", "argon2"),
    ("containers", "pyfvde"),
    ("offload_gpu", "pyopencl"),
    ("offload_gpu", "pycuda"),
    ("instrumentation", "frida"),
    ("instrumentation", "lief"),
    ("instrumentation", "capstone"),
    ("disassembly", "pyhidra"),
    ("hardware", "leechcore"),
    ("hardware", "chipsec"),
    ("sigma", "yara"),
    ("ml", "numpy"),
    ("ml", "scipy"),
    ("linux_monitoring", "bcc"),
    ("linux_monitoring", "pyroute2"),
    ("remote_acquisition", "paramiko"),
)


def probe_module(name: str) -> tuple[bool, str, str]:
    try:
        mod = importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001
        return False, "", str(exc)
    version = getattr(mod, "__version__", "")
    return True, str(version), ""


def run(as_json: bool) -> int:
    ctx = AnalysisContext.for_testing()
    platform = ctx.platform
    report: list[ExtraStatus] = []
    for extra, module in EXTRAS:
        installed, version, err = probe_module(module)
        report.append(
            ExtraStatus(extra=extra, module=module, installed=installed,
                        version=version, error=err if not installed else "")
        )

    if as_json:
        payload = {
            "session_id": ctx.session_id,
            "platform": {
                "os": platform.os.value,
                "arch": platform.arch,
                "kernel": platform.kernel_version,
                "capabilities": sorted(platform.capabilities),
            },
            "extras": [asdict(r) for r in report],
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print(f"Deep View doctor — session {ctx.session_id}")
    print(f"  OS:             {platform.os.value}")
    print(f"  Arch:           {platform.arch}")
    print(f"  Kernel:         {platform.kernel_version}")
    caps = ", ".join(sorted(platform.capabilities)) or "(none)"
    print(f"  Capabilities:   {caps}")
    print()
    print(f"  {'Extra':<22} {'Module':<16} {'Status':<12} {'Version'}")
    print(f"  {'-' * 22} {'-' * 16} {'-' * 12} {'-' * 20}")
    for r in report:
        status = "available" if r.installed else "missing"
        print(f"  {r.extra:<22} {r.module:<16} {status:<12} {r.version}")

    installed = sum(1 for r in report if r.installed)
    print()
    print(f"Summary: {installed}/{len(report)} probed modules available.")
    print("Install missing pieces via e.g. `pip install -e '.[containers,storage]'`.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()
    return run(as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
