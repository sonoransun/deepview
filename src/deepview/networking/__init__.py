"""Live network packet mangling subsystem.

This is a dual-use capability scoped for authorized security testing,
CTF work, honeypot research, and defensive R&D on hosts the operator
controls. Every entry point into the mangle engine requires root,
explicit ``--enable-mangle`` opt-in, and a loaded YAML ruleset; the
default verdict is always ACCEPT (fail-open) so an engine crash or
an unmatched packet never wedges the host.

Nothing here imports the dashboard package at load time; the mangle
engine runs headless via ``deepview netmangle run`` and only meets
the dashboard through :class:`deepview.cli.dashboard.panels.ManglePanel`
which subscribes to the engine's event stream on the core
:class:`EventBus`.
"""
from __future__ import annotations

from deepview.networking.actions import (
    Action,
    AcceptAction,
    CorruptAction,
    DelayAction,
    DropAction,
    MarkAction,
    ObserveAction,
    RewriteAction,
    action_from_mapping,
)
from deepview.networking.engine import MangleEngine, MangleStats
from deepview.networking.packet import PacketView
from deepview.networking.ruleset import MangleRule, MangleRuleset, MangleRuleLoadError
from deepview.networking.parser import ParsedPacket, parse_packet

__all__ = [
    "Action",
    "AcceptAction",
    "CorruptAction",
    "DelayAction",
    "DropAction",
    "MarkAction",
    "ObserveAction",
    "RewriteAction",
    "action_from_mapping",
    "MangleEngine",
    "MangleStats",
    "PacketView",
    "MangleRule",
    "MangleRuleset",
    "MangleRuleLoadError",
    "ParsedPacket",
    "parse_packet",
]
