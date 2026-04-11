"""A thin field view over a :class:`ParsedPacket` for filter evaluation.

``FilterExpr.evaluate`` walks dot-path field names on a
``MonitorEvent``. We want mangle rules to reuse the exact same DSL,
so ``PacketView`` exposes header fields like attribute chains:

    packet.ipv4.dst
    packet.tcp.dport
    packet.tcp.syn
    packet.total_len
    packet.direction
    packet.payload_len

``PacketView`` never stores raw packet bytes beyond what the parser
already keeps, and never mutates them. Rewrites happen via
:func:`deepview.networking.parser.rebuild_packet`.
"""
from __future__ import annotations

from dataclasses import dataclass

from deepview.networking.parser import ParsedPacket


@dataclass
class PacketView:
    """Attribute-chain view over a parsed packet, plus light metadata."""

    parsed: ParsedPacket
    direction: str = "out"  # "out" for OUTPUT chain, "in" for INPUT chain
    queue: int = 0

    # Convenience fields for FilterExpr dot-paths.
    @property
    def ipv4(self) -> object:
        return self.parsed.ipv4

    @property
    def ipv6(self) -> object:
        return self.parsed.ipv6

    @property
    def tcp(self) -> object:
        return self.parsed.tcp

    @property
    def udp(self) -> object:
        return self.parsed.udp

    @property
    def icmp(self) -> object:
        return self.parsed.icmp

    @property
    def total_len(self) -> int:
        return self.parsed.total_len

    @property
    def payload_len(self) -> int:
        return self.parsed.payload_length

    @property
    def is_fragmented(self) -> bool:
        return self.parsed.is_fragmented

    @property
    def ip_version(self) -> int:
        return self.parsed.ip_version

    # ------------------------------------------------------------------
    # The MangleEngine wraps every packet in a `MatchEnvelope` that
    # puts PacketView under a top-level "packet" attribute so rules
    # read `packet.ipv4.dst == ...` naturally.
    # ------------------------------------------------------------------


@dataclass
class MatchEnvelope:
    """Top-level evaluation context for mangle FilterExpr predicates."""

    packet: PacketView
