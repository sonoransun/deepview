"""``deepview sidechannel`` — rf-SQUID / dc-SQUID magnetometry on a SUT.

AUTHORIZED-TESTING SCOPE ONLY. ``capture`` requires ``--authorization-statement``
(logged into the capture metadata for an audit trail) and dry-runs unless
``--confirm`` is passed — the same fail-safe pattern as ``deepview remote-image``.
Probes lazily bind to optional DAQ hardware; the ``simulated-squid`` probe runs
everywhere for analysis development.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.table import Table


@click.group()
def sidechannel() -> None:
    """Magnetic / EM side-channel acquisition and analysis (authorized testing)."""


def _build_probe(context: object, name: str, *, mode: str, signal_hz: float, seed: int):
    from deepview.sidechannel.dc_squid import DCSquidProbe
    from deepview.sidechannel.rf_squid import RFSquidProbe
    from deepview.sidechannel.simulated import SimulatedSquidProbe

    cfg = context.config.sidechannel  # type: ignore[attr-defined]
    if name == "simulated-squid":
        return SimulatedSquidProbe(mode=mode, signal_hz=signal_hz, seed=seed)
    if name == "dc-squid":
        return DCSquidProbe(
            device=cfg.squid_device,
            driver=cfg.squid_driver,
            flux_bias=cfg.squid_flux_bias,
            gain=cfg.squid_gain,
        )
    if name == "rf-squid":
        return RFSquidProbe(
            device=cfg.squid_device,
            driver=cfg.squid_driver,
            rf_bias_hz=cfg.squid_rf_bias_hz,
            gain=cfg.squid_gain,
        )
    raise click.BadParameter(f"unknown probe: {name}")


@sidechannel.command("probes")
@click.pass_context
def list_probes(ctx: click.Context) -> None:
    """List side-channel probes and whether each can capture right now."""
    from deepview.sidechannel.manager import SideChannelManager

    console = ctx.obj["console"]
    mgr = SideChannelManager.from_context(ctx.obj["context"])
    table = Table(title="Side-channel probes", min_width=40)
    table.add_column("Probe", style="cyan")
    table.add_column("Available")
    table.add_column("Privilege")
    for name in mgr.probe_names():
        probe = mgr.get_probe_class(name)()
        avail = "[green]yes[/green]" if probe.is_available() else "[dim]no[/dim]"
        table.add_row(name, avail, probe.requires_privileges().value)
    console.print(table)


@sidechannel.command("capture")
@click.option("--probe", "probe_name", default="simulated-squid",
              type=click.Choice(["simulated-squid", "dc-squid", "rf-squid"]),
              help="Probe to capture from")
@click.option("--subject", required=True, help="Subject-under-test label (audit)")
@click.option("--device-class", default="", help="SUT device class (mcu/fpga/...)")
@click.option("--samples", default=4096, type=int, help="Number of samples")
@click.option("--sample-rate", "sample_rate", default=None, type=int,
              help="Sample rate in Hz (probe default if omitted)")
@click.option("--mode", default="dc", type=click.Choice(["dc", "rf"]),
              help="Simulated probe emanation mode")
@click.option("--signal-hz", default=12500.0, type=float, help="Simulated signal Hz")
@click.option("--seed", default=1, type=int, help="Simulated probe seed")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write the capture (JSON) here")
@click.option("--authorization-statement", "authorization", default=None,
              help="Free-text authorization, logged into the capture metadata")
@click.option("--confirm", is_flag=True, help="Actually capture (else dry-run)")
@click.pass_context
def capture(
    ctx: click.Context,
    probe_name: str,
    subject: str,
    device_class: str,
    samples: int,
    sample_rate: int | None,
    mode: str,
    signal_hz: float,
    seed: int,
    output: str | None,
    authorization: str | None,
    confirm: bool,
) -> None:
    """Capture a side-channel trace from a subject under test."""
    from deepview.interfaces.sidechannel import SubjectUnderTest
    from deepview.sidechannel.manager import SideChannelManager

    console = ctx.obj["console"]
    context = ctx.obj["context"]

    if not authorization:
        console.print(
            "[red]--authorization-statement is required: side-channel capture "
            "is for authorized testing only.[/red]"
        )
        raise click.Abort()

    probe = _build_probe(context, probe_name, mode=mode, signal_hz=signal_hz, seed=seed)
    if not confirm:
        console.print("[yellow]DRY RUN[/yellow] (pass --confirm to capture)")
        console.print(f"  probe:    {probe_name}")
        console.print(f"  subject:  {subject} ({device_class or 'unspecified'})")
        console.print(f"  samples:  {samples} @ {sample_rate or 'default'} Hz")
        console.print(f"  available: {probe.is_available()}")
        console.print(f"  authorization: {authorization}")
        return

    if not probe.is_available():
        console.print(
            f"[red]{probe_name} is not available (no DAQ driver). Use "
            "--probe simulated-squid for offline work.[/red]"
        )
        raise click.Abort()

    mgr = SideChannelManager.from_context(context)
    sut = SubjectUnderTest(label=subject, device_class=device_class)
    result = mgr.capture(probe, sut, samples=samples, sample_rate_hz=sample_rate)

    console.print(
        f"[green]captured[/green] {result.sample_count} samples "
        f"({result.duration_s * 1000:.3f} ms) sha256={result.hash_sha256[:16]}…"
    )
    if output:
        payload = {
            "probe": result.probe_name,
            "subject": {"label": sut.label, "device_class": sut.device_class},
            "sample_rate_hz": result.sample_rate_hz,
            "channel": result.channel,
            "units": result.units,
            "sha256": result.hash_sha256,
            "authorization_statement": authorization,
            "samples": list(result.samples),
        }
        Path(output).write_text(json.dumps(payload))
        console.print(f"[green]written to {output}[/green]")


@sidechannel.command("analyze")
@click.option("--capture", "capture_file", required=True, type=click.Path(exists=True),
              help="Capture JSON produced by `sidechannel capture -o`")
@click.option("--nperseg", default=256, type=int, help="Welch segment length")
@click.pass_context
def analyze(ctx: click.Context, capture_file: str, nperseg: int) -> None:
    """Run PSD analysis on a saved capture (needs the sidechannel extra)."""
    from deepview.interfaces.sidechannel import ProbeCapture, SubjectUnderTest

    console = ctx.obj["console"]
    data = json.loads(Path(capture_file).read_text())
    subj = data.get("subject", {})
    cap = ProbeCapture(
        probe_name=data.get("probe", "unknown"),
        subject=SubjectUnderTest(
            label=subj.get("label", ""), device_class=subj.get("device_class", "")
        ),
        sample_rate_hz=int(data["sample_rate_hz"]),
        samples=tuple(float(x) for x in data["samples"]),
        channel=data.get("channel", "magnetic"),
        units=data.get("units", "phi0"),
        hash_sha256=data.get("sha256", ""),
    )
    try:
        from deepview.sidechannel import analysis
        dominant = analysis.dominant_frequency(cap, nperseg=nperseg)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.Abort() from exc

    table = Table(title=f"Analysis: {cap.probe_name}", min_width=40)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_row("samples", str(cap.sample_count))
    table.add_row("sample_rate_hz", str(cap.sample_rate_hz))
    table.add_row("duration_ms", f"{cap.duration_s * 1000:.3f}")
    table.add_row("dominant_frequency_hz", f"{dominant:.1f}")
    table.add_row("sha256", cap.hash_sha256[:32] + "…" if cap.hash_sha256 else "—")
    console.print(table)
