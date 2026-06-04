"""``SideChannelManager`` — probe registry + authorized capture orchestration.

Built from an :class:`AnalysisContext` (``SideChannelManager.from_context(ctx)``)
so it picks up config + the event bus + the artifact store. ``capture`` publishes
the ``SideChannelCapture*`` lifecycle events and records a chain-of-custody
artifact (probe, subject, sample count, SHA256).
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

from deepview.core.events import (
    SideChannelCaptureCompletedEvent,
    SideChannelCaptureProgressEvent,
    SideChannelCaptureStartedEvent,
)
from deepview.core.logging import get_logger
from deepview.interfaces.sidechannel import (
    ProbeCapture,
    SideChannelProbe,
    SubjectUnderTest,
)
from deepview.sidechannel.dc_squid import DCSquidProbe
from deepview.sidechannel.rf_squid import RFSquidProbe
from deepview.sidechannel.simulated import SimulatedSquidProbe

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext

log = get_logger("sidechannel.manager")

_BUILTIN_PROBES: dict[str, type[SideChannelProbe]] = {
    SimulatedSquidProbe.probe_name(): SimulatedSquidProbe,
    DCSquidProbe.probe_name(): DCSquidProbe,
    RFSquidProbe.probe_name(): RFSquidProbe,
}


class SideChannelManager:
    """Registry of side-channel probes plus an audited capture path."""

    def __init__(self, context: AnalysisContext) -> None:
        self._context = context
        self._probes: dict[str, type[SideChannelProbe]] = dict(_BUILTIN_PROBES)

    @classmethod
    def from_context(cls, context: AnalysisContext) -> SideChannelManager:
        return cls(context)

    def probe_names(self) -> list[str]:
        return sorted(self._probes)

    def get_probe_class(self, name: str) -> type[SideChannelProbe]:
        if name not in self._probes:
            raise KeyError(f"unknown side-channel probe: {name}")
        return self._probes[name]

    def register_probe(self, probe_cls: type[SideChannelProbe]) -> None:
        self._probes[probe_cls.probe_name()] = probe_cls

    def capture(
        self,
        probe: SideChannelProbe,
        subject: SubjectUnderTest,
        *,
        samples: int = 4096,
        sample_rate_hz: int | None = None,
    ) -> ProbeCapture:
        """Run a capture, publish lifecycle events, and record an artifact."""
        bus = self._context.events
        bus.publish(
            SideChannelCaptureStartedEvent(
                probe=probe.probe_name(), subject=subject.label, samples=samples
            )
        )
        start = time.time()
        result = probe.capture(subject, samples=samples, sample_rate_hz=sample_rate_hz)
        bus.publish(
            SideChannelCaptureProgressEvent(
                probe=probe.probe_name(),
                samples_done=result.sample_count,
                samples_total=samples,
                stage="hashing",
            )
        )
        bus.publish(
            SideChannelCaptureCompletedEvent(
                probe=probe.probe_name(),
                subject=subject.label,
                samples=result.sample_count,
                sha256=result.hash_sha256,
                elapsed_s=time.time() - start,
            )
        )
        self._context.artifacts.add(
            "sidechannel_captures",
            {
                "name": f"capture:{probe.probe_name()}",
                "probe": probe.probe_name(),
                "subject": subject.label,
                "device_class": subject.device_class,
                "samples": result.sample_count,
                "sample_rate_hz": result.sample_rate_hz,
                "channel": result.channel,
                "units": result.units,
                "sha256": result.hash_sha256,
            },
        )
        log.info(
            "sidechannel_capture",
            probe=probe.probe_name(),
            subject=subject.label,
            samples=result.sample_count,
            sha256=result.hash_sha256[:16],
        )
        return result
