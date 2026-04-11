"""YAML loader + rule matching tests for MangleRuleset."""
from __future__ import annotations

import socket
import struct
import textwrap

import pytest

from deepview.networking.packet import MatchEnvelope, PacketView
from deepview.networking.parser import parse_packet
from deepview.networking.ruleset import MangleRuleLoadError, MangleRuleset


def _make_udp_packet(src="10.0.0.1", dst="10.0.0.2", sport=5353, dport=53, payload=b"q") -> PacketView:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + len(payload),
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        socket.inet_pton(socket.AF_INET, src),
        socket.inet_pton(socket.AF_INET, dst),
    )
    parsed = parse_packet(ip + udp + payload)
    assert parsed is not None
    return PacketView(parsed=parsed)


class TestLoadYaml:
    def test_minimal_ruleset(self, tmp_path):
        path = tmp_path / "r.yaml"
        path.write_text(
            textwrap.dedent(
                """
                queue: 7
                rules:
                  - id: drop_dns
                    match: 'packet.udp.dport == 53'
                    action:
                      type: drop
                """
            )
        )
        rs = MangleRuleset.load_yaml(path)
        assert rs.queue == 7
        assert len(rs) == 1
        assert rs.source_sha256

    def test_missing_match_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("rules:\n  - id: r1\n    action: {type: drop}\n")
        with pytest.raises(MangleRuleLoadError, match="match"):
            MangleRuleset.load_yaml(path)

    def test_unknown_action_type_raises(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text(
            "rules:\n  - id: r1\n    match: 'packet.tcp.dport == 80'\n    action: {type: explode}\n"
        )
        with pytest.raises(MangleRuleLoadError, match="explode"):
            MangleRuleset.load_yaml(path)

    def test_builtin_honeypot_loads(self):
        from pathlib import Path

        rs = MangleRuleset.load_yaml(
            Path(__file__).parents[3] / "src/deepview/networking/builtin_rules/network_honeypot.yaml"
        )
        assert len(rs) >= 3


class TestMatching:
    def test_first_match_wins(self, tmp_path):
        path = tmp_path / "r.yaml"
        path.write_text(
            textwrap.dedent(
                """
                rules:
                  - id: drop_dns
                    match: 'packet.udp.dport == 53'
                    action: {type: drop}
                  - id: accept_all
                    match: 'packet.total_len > 0'
                    action: {type: accept}
                """
            )
        )
        rs = MangleRuleset.load_yaml(path)
        env = MatchEnvelope(packet=_make_udp_packet())
        matched = rs.first_match(env)
        assert matched is not None
        assert matched.id == "drop_dns"

    def test_no_match_returns_none(self, tmp_path):
        path = tmp_path / "r.yaml"
        path.write_text(
            textwrap.dedent(
                """
                rules:
                  - id: drop_to_c2
                    match: 'packet.ipv4.dst == "192.0.2.66"'
                    action: {type: drop}
                """
            )
        )
        rs = MangleRuleset.load_yaml(path)
        env = MatchEnvelope(packet=_make_udp_packet(dst="10.0.0.2"))
        assert rs.first_match(env) is None
