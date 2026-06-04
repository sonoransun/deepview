"""Capture and analyse a simulated rf-SQUID / dc-SQUID magnetic side channel.

Demonstrates:

* building a :class:`~deepview.sidechannel.SideChannelManager` from a context;
* capturing a deterministic trace from the hardware-free
  :class:`~deepview.sidechannel.SimulatedSquidProbe` (no DAQ required);
* the SHA256 chain-of-custody on every :class:`ProbeCapture`;
* subscribing to the ``SideChannelCapture*`` lifecycle events; and
* recovering the injected tone with the PSD analysis helpers (when the
  ``sidechannel`` extra — numpy/scipy — is installed).

This is authorized-testing tooling: in the field you would substitute the
``dc-squid`` / ``rf-squid`` probe (real DAQ) and pass an authorization
statement through the CLI. The simulated probe exists so the capture +
analysis pipeline can be developed and tested offline.

Usage:
    python examples/13_squid_capture_simulated.py --samples 8192 --signal-hz 40000
"""
from __future__ import annotations

import argparse

from deepview.core.context import AnalysisContext
from deepview.core.events import (
    SideChannelCaptureCompletedEvent,
    SideChannelCaptureStartedEvent,
)
from deepview.interfaces.sidechannel import SubjectUnderTest
from deepview.sidechannel import SideChannelManager, SimulatedSquidProbe


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--samples", type=int, default=8192)
    p.add_argument("--sample-rate", type=int, default=1_000_000)
    p.add_argument("--signal-hz", type=float, default=40_000.0)
    p.add_argument("--mode", choices=["dc", "rf"], default="dc")
    p.add_argument("--seed", type=int, default=1)
    return p


def main() -> int:
    args = _parser().parse_args()

    ctx = AnalysisContext.for_testing()
    ctx.events.subscribe(
        SideChannelCaptureStartedEvent,
        lambda e: print(f"[started] probe={e.probe} subject={e.subject} samples={e.samples}"),
    )
    ctx.events.subscribe(
        SideChannelCaptureCompletedEvent,
        lambda e: print(f"[done]    sha256={e.sha256[:16]}… in {e.elapsed_s * 1e3:.2f} ms"),
    )

    manager = SideChannelManager.from_context(ctx)
    probe = SimulatedSquidProbe(mode=args.mode, signal_hz=args.signal_hz, seed=args.seed)
    subject = SubjectUnderTest(label="demo-board", device_class="mcu")

    capture = manager.capture(
        probe, subject, samples=args.samples, sample_rate_hz=args.sample_rate
    )
    print(
        f"captured {capture.sample_count} samples "
        f"({capture.duration_s * 1e3:.3f} ms) on the {capture.channel} channel"
    )

    try:
        from deepview.sidechannel import analysis

        dominant = analysis.dominant_frequency(capture, nperseg=min(2048, args.samples))
        print(f"dominant frequency ≈ {dominant:,.0f} Hz (injected {args.signal_hz:,.0f} Hz)")
    except RuntimeError as exc:
        print(f"[analysis skipped] {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
