"""Side-channel acquisition + analysis (rf-SQUID / dc-SQUID magnetometry).

Authorized-testing scope only — see :mod:`deepview.interfaces.sidechannel`.
"""
from __future__ import annotations

from deepview.sidechannel.dc_squid import DCSquidProbe
from deepview.sidechannel.manager import SideChannelManager
from deepview.sidechannel.rf_squid import RFSquidProbe
from deepview.sidechannel.simulated import SimulatedSquidProbe

__all__ = [
    "SideChannelManager",
    "SimulatedSquidProbe",
    "DCSquidProbe",
    "RFSquidProbe",
]
