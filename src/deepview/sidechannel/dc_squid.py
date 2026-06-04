"""DC-SQUID magnetometer probe (direct flux-coupled readout).

A dc-SQUID couples the subject's magnetic flux directly into the SQUID loop and
reads it back through a flux-locked loop and a DAQ. There is no single standard
Python binding for SQUID DAQ hardware, so the hardware seam is a lazily-imported
driver module named in config (default ``squidpy``). When the driver is absent
the probe reports ``is_available() == False`` and ``capture`` raises a clear,
actionable error pointing operators at :class:`SimulatedSquidProbe` for offline
work.

Driver contract (documented seam)::

    driver.open(device) -> session
    session.read_flux(count, sample_rate_hz, flux_bias, gain) -> Sequence[float]
    session.close()  # optional
"""
from __future__ import annotations

import importlib

from deepview.core.logging import get_logger
from deepview.core.types import PrivilegeLevel
from deepview.sidechannel._base import MagnetometerProbe

log = get_logger("sidechannel.dc_squid")


class DCSquidProbe(MagnetometerProbe):
    """Direct flux-coupled SQUID magnetometer."""

    channel = "magnetic"
    units = "phi0"

    def __init__(
        self,
        *,
        device: str = "",
        driver: str = "squidpy",
        flux_bias: float = 0.0,
        gain: float = 1.0,
    ) -> None:
        self.device = device
        self.driver = driver
        self.flux_bias = flux_bias
        self.gain = gain

    @classmethod
    def probe_name(cls) -> str:
        return "dc-squid"

    def requires_privileges(self) -> PrivilegeLevel:
        # Raw DAQ device access typically needs elevated privilege.
        return PrivilegeLevel.ROOT

    def _load_driver(self) -> object:
        return importlib.import_module(self.driver)

    def is_available(self) -> bool:
        try:
            self._load_driver()
        except Exception:  # noqa: BLE001 - any import/driver error → unavailable
            return False
        return True

    def _read_samples(self, count: int, sample_rate_hz: int) -> list[float]:
        try:
            driver = self._load_driver()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"dc-squid driver {self.driver!r} unavailable: {exc}. "
                "Use SimulatedSquidProbe (or `--probe simulated-squid`) for "
                "offline analysis."
            ) from exc
        session = driver.open(self.device)  # type: ignore[attr-defined]
        try:
            readings = session.read_flux(
                count, sample_rate_hz, self.flux_bias, self.gain
            )
            return [float(x) for x in readings]
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
