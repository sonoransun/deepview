"""Hand-constructed packet round-trip tests for the stdlib parser."""
from __future__ import annotations

import socket
import struct

import pytest

from deepview.networking.parser import parse_packet, rebuild_packet


def _ipv4_header(
    *,
    total_len: int,
    protocol: int,
    src: str,
    dst: str,
    ihl: int = 5,
    ttl: int = 64,
    identification: int = 0,
    flags: int = 0,
    frag_offset: int = 0,
) -> bytes:
    ver_ihl = (4 << 4) | ihl
    tos = 0
    frag_word = (flags << 13) | frag_offset
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        identification,
        frag_word,
        ttl,
        protocol,
        0,  # checksum placeholder; parser doesn't validate
        socket.inet_pton(socket.AF_INET, src),
        socket.inet_pton(socket.AF_INET, dst),
    )
    return hdr


def _tcp_header(
    *,
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: int = 0,
    window: int = 0x2000,
    data_offset: int = 5,
) -> bytes:
    doff_flags = (data_offset << 12) | flags
    return struct.pack(
        ">HHIIHHHH",
        sport,
        dport,
        seq,
        ack,
        doff_flags,
        window,
        0,  # checksum placeholder
        0,  # urgent
    )


def _udp_header(sport: int, dport: int, length: int) -> bytes:
    return struct.pack(">HHHH", sport, dport, length, 0)


class TestParseIPv4:
    def test_parse_tcp_packet(self):
        payload = b"hello world"
        tcp_hdr = _tcp_header(sport=40000, dport=443, flags=0x18)
        total_len = 20 + len(tcp_hdr) + len(payload)
        ip_hdr = _ipv4_header(
            total_len=total_len,
            protocol=socket.IPPROTO_TCP,
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        raw = ip_hdr + tcp_hdr + payload
        parsed = parse_packet(raw)
        assert parsed is not None
        assert parsed.ipv4 is not None
        assert parsed.ipv4.src == "10.0.0.1"
        assert parsed.ipv4.dst == "10.0.0.2"
        assert parsed.tcp is not None
        assert parsed.tcp.sport == 40000
        assert parsed.tcp.dport == 443
        assert parsed.payload == payload

    def test_parse_udp_packet(self):
        payload = b"dns-query-go-here"
        udp_len = 8 + len(payload)
        udp_hdr = _udp_header(sport=5353, dport=53, length=udp_len)
        total_len = 20 + udp_len
        ip_hdr = _ipv4_header(
            total_len=total_len,
            protocol=socket.IPPROTO_UDP,
            src="192.168.1.10",
            dst="8.8.8.8",
        )
        raw = ip_hdr + udp_hdr + payload
        parsed = parse_packet(raw)
        assert parsed is not None
        assert parsed.udp is not None
        assert parsed.udp.dport == 53
        assert parsed.payload == payload

    def test_parse_too_short(self):
        assert parse_packet(b"\x45") is None
        assert parse_packet(b"") is None

    def test_parse_wrong_version(self):
        assert parse_packet(b"\x20" + b"\x00" * 39) is None

    def test_fragmented_flag(self):
        ip_hdr = _ipv4_header(
            total_len=40,
            protocol=socket.IPPROTO_TCP,
            src="1.1.1.1",
            dst="2.2.2.2",
            flags=0x1,  # MF set
        )
        parsed = parse_packet(ip_hdr + b"\x00" * 20)
        assert parsed is not None
        assert parsed.is_fragmented


class TestRebuild:
    def test_rebuild_udp_replaces_payload_and_length(self):
        original_payload = b"example.com"
        udp_len = 8 + len(original_payload)
        udp_hdr = _udp_header(sport=5353, dport=53, length=udp_len)
        total_len = 20 + udp_len
        ip_hdr = _ipv4_header(
            total_len=total_len,
            protocol=socket.IPPROTO_UDP,
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        raw = ip_hdr + udp_hdr + original_payload
        parsed = parse_packet(raw)
        assert parsed is not None

        new_payload = b"honeypot.local"
        new_raw = rebuild_packet(parsed, new_payload=new_payload)
        reparsed = parse_packet(new_raw)
        assert reparsed is not None
        assert reparsed.payload == new_payload
        assert reparsed.udp is not None
        assert reparsed.udp.length == 8 + len(new_payload)
        # Total length updated in the IPv4 header too.
        assert reparsed.ipv4 is not None
        assert reparsed.ipv4.total_length == 20 + 8 + len(new_payload)

    def test_rebuild_tcp_updates_total_length(self):
        payload = b"hi"
        tcp_hdr = _tcp_header(sport=1234, dport=80, flags=0x18)
        ip_hdr = _ipv4_header(
            total_len=20 + len(tcp_hdr) + len(payload),
            protocol=socket.IPPROTO_TCP,
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        raw = ip_hdr + tcp_hdr + payload
        parsed = parse_packet(raw)
        assert parsed is not None
        new_raw = rebuild_packet(parsed, new_payload=b"hello world")
        reparsed = parse_packet(new_raw)
        assert reparsed is not None
        assert reparsed.payload == b"hello world"
        assert reparsed.ipv4.total_length == 20 + 20 + len(b"hello world")

    def test_rebuild_fragment_refuses(self):
        ip_hdr = _ipv4_header(
            total_len=28,
            protocol=socket.IPPROTO_UDP,
            src="10.0.0.1",
            dst="10.0.0.2",
            flags=0x1,
        )
        parsed = parse_packet(ip_hdr + _udp_header(1, 2, 8))
        assert parsed is not None
        with pytest.raises(ValueError):
            rebuild_packet(parsed, new_payload=b"x")
