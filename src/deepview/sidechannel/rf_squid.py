"""RF-SQUID magnetometer probe (RF tank-circuit / flux-modulated readout).

An rf-SQUID has a single Josephson junction in a loop inductively coupled to an
RF-biased tank circuit; the subject's flux modulates the tank's resonance, which
is demodulated to a flux reading. Same lazily-imported driver seam as the
dc-SQUID probe — see :mod:`deepview.sidechannel.dc_squid` — with an extra
``rf_bias_hz`` parameter threaded to the driver.

Driver contract (documented seam)::

    driver.open(device) -> session
    session.read_flux_rf(count, sample_rate_hz, rf_bias_hz, gain) -> Sequence[float]
    session.close()  # optional
"""
from __future__ import annotations

import importlib

from deepview.core.logging import get_logger
from deepview.core.types import PrivilegeLevel
from deepview.sidechannel._base import MagnetometerProbe

log = get_logger("sidechannel.rf_squid")


class RFSquidProbe(MagnetometerProbe):
    """RF tank-circuit SQUID magnetometer."""

    channel = "magnetic"
    units = "phi0"

    def __init__(
        self,
        *,
        device: str = "",
        driver: str = "squidpy",
        rf_bias_hz: float = 20_000_000.0,
        gain: float = 1.0,
    ) -> None:
        self.device = device
        self.driver = driver
        self.rf_bias_hz = rf_bias_hz
        self.gain = gain

    @classmethod
    def probe_name(cls) -> str:
        return "rf-squid"

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def _load_driver(self) -> object:
        return importlib.import_module(self.driver)

    def is_available(self) -> bool:
        try:
            self._load_driver()
        except Exception:  # noqa: BLE001
            return False
        return True

    def _read_samples(self, count: int, sample_rate_hz: int) -> list[float]:
        try:
            driver = self._load_driver()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"rf-squid driver {self.driver!r} unavailable: {exc}. "
                "Use SimulatedSquidProbe (or `--probe simulated-squid`) for "
                "offline analysis."
            ) from exc
        session = driver.open(self.device)  # type: ignore[attr-defined]
        try:
            readings = session.read_flux_rf(
                count, sample_rate_hz, self.rf_bias_hz, self.gain
            )
            return [float(x) for x in readings]
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
