"""Stdlib struct-based IPv4/IPv6/TCP/UDP/ICMP header parser.

We intentionally do not depend on scapy. This module parses and
re-emits enough of the common header fields to let the mangle
engine:

* evaluate ``FilterExpr`` predicates over header fields
* rewrite payload bytes and recompute checksums
* reject fragmented packets (we refuse to rewrite fragments)

The API is deliberately small:

    parsed = parse_packet(raw_bytes)
    # parsed.ip_version, .total_len, .src, .dst, .payload_offset, .tcp, .udp, .icmp, ...

    new_bytes = rebuild_packet(parsed, new_payload=b"...")
    # recomputes L3 + L4 checksums and returns the complete packet.

``parse_packet`` returns ``None`` when the input is too short or not
an IPv4/IPv6 packet — callers in the mangle engine verdict ACCEPT in
that case (fail-open) and log a warning.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Layer data classes
# ---------------------------------------------------------------------------


@dataclass
class IPv4Header:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    frag_offset: int
    ttl: int
    protocol: int
    checksum: int
    src: str
    dst: str

    @property
    def is_fragmented(self) -> bool:
        return bool(self.flags & 0x1) or self.frag_offset != 0


@dataclass
class IPv6Header:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src: str
    dst: str


@dataclass
class TCPHeader:
    sport: int
    dport: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent: int
    length: int  # total TCP header + payload

    @property
    def fin(self) -> bool: return bool(self.flags & 0x01)
    @property
    def syn(self) -> bool: return bool(self.flags & 0x02)
    @property
    def rst(self) -> bool: return bool(self.flags & 0x04)
    @property
    def psh(self) -> bool: return bool(self.flags & 0x08)
    @property
    def ack_flag(self) -> bool: return bool(self.flags & 0x10)
    @property
    def urg(self) -> bool: return bool(self.flags & 0x20)


@dataclass
class UDPHeader:
    sport: int
    dport: int
    length: int
    checksum: int


@dataclass
class ICMPHeader:
    type: int
    code: int
    checksum: int


@dataclass
class ParsedPacket:
    """Lightweight parse result. Only the fields we care about are filled in."""

    raw: bytes
    ip_version: int
    ipv4: IPv4Header | None = None
    ipv6: IPv6Header | None = None
    tcp: TCPHeader | None = None
    udp: UDPHeader | None = None
    icmp: ICMPHeader | None = None
    l3_offset: int = 0
    l4_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0

    @property
    def is_fragmented(self) -> bool:
        if self.ipv4 is not None:
            return self.ipv4.is_fragmented
        return False

    @property
    def total_len(self) -> int:
        if self.ipv4 is not None:
            return self.ipv4.total_length
        if self.ipv6 is not None:
            return self.ipv6.payload_length + 40
        return len(self.raw)

    @property
    def payload(self) -> bytes:
        return bytes(self.raw[self.payload_offset : self.payload_offset + self.payload_length])


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_packet(data: bytes) -> Optional[ParsedPacket]:
    """Top-level parser: decide IPv4 vs IPv6 vs unparseable."""
    if len(data) < 1:
        return None
    version = (data[0] >> 4) & 0xF
    if version == 4:
        return _parse_ipv4(data)
    if version == 6:
        return _parse_ipv6(data)
    return None


def _parse_ipv4(data: bytes) -> Optional[ParsedPacket]:
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    ihl = ver_ihl & 0xF
    header_len = ihl * 4
    if header_len < 20 or len(data) < header_len:
        return None
    tos = data[1]
    total_length = int.from_bytes(data[2:4], "big")
    identification = int.from_bytes(data[4:6], "big")
    frag_word = int.from_bytes(data[6:8], "big")
    flags = (frag_word >> 13) & 0x7
    frag_offset = frag_word & 0x1FFF
    ttl = data[8]
    protocol = data[9]
    checksum = int.from_bytes(data[10:12], "big")
    src = socket.inet_ntop(socket.AF_INET, bytes(data[12:16]))
    dst = socket.inet_ntop(socket.AF_INET, bytes(data[16:20]))

    hdr = IPv4Header(
        version=4,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        identification=identification,
        flags=flags,
        frag_offset=frag_offset,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src=src,
        dst=dst,
    )
    parsed = ParsedPacket(
        raw=bytes(data),
        ip_version=4,
        ipv4=hdr,
        l3_offset=0,
        l4_offset=header_len,
    )
    _parse_l4(parsed, protocol, header_len)
    return parsed


def _parse_ipv6(data: bytes) -> Optional[ParsedPacket]:
    if len(data) < 40:
        return None
    first_word = int.from_bytes(data[0:4], "big")
    version = (first_word >> 28) & 0xF
    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF
    payload_length = int.from_bytes(data[4:6], "big")
    next_header = data[6]
    hop_limit = data[7]
    src = socket.inet_ntop(socket.AF_INET6, bytes(data[8:24]))
    dst = socket.inet_ntop(socket.AF_INET6, bytes(data[24:40]))
    hdr = IPv6Header(
        version=version,
        traffic_class=traffic_class,
        flow_label=flow_label,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src=src,
        dst=dst,
    )
    parsed = ParsedPacket(
        raw=bytes(data),
        ip_version=6,
        ipv6=hdr,
        l3_offset=0,
        l4_offset=40,
    )
    # Note: we don't walk IPv6 extension headers; if next_header isn't
    # one of the L4 protocols we recognise, L4 stays None.
    _parse_l4(parsed, next_header, 40)
    return parsed


def _parse_l4(parsed: ParsedPacket, protocol: int, l4_offset: int) -> None:
    data = parsed.raw
    if protocol == socket.IPPROTO_TCP:
        if len(data) < l4_offset + 20:
            return
        sport = int.from_bytes(data[l4_offset : l4_offset + 2], "big")
        dport = int.from_bytes(data[l4_offset + 2 : l4_offset + 4], "big")
        seq = int.from_bytes(data[l4_offset + 4 : l4_offset + 8], "big")
        ack = int.from_bytes(data[l4_offset + 8 : l4_offset + 12], "big")
        doff_flags = int.from_bytes(data[l4_offset + 12 : l4_offset + 14], "big")
        data_offset = (doff_flags >> 12) & 0xF
        flags = doff_flags & 0x3F
        window = int.from_bytes(data[l4_offset + 14 : l4_offset + 16], "big")
        checksum = int.from_bytes(data[l4_offset + 16 : l4_offset + 18], "big")
        urgent = int.from_bytes(data[l4_offset + 18 : l4_offset + 20], "big")
        header_len = data_offset * 4
        parsed.tcp = TCPHeader(
            sport=sport,
            dport=dport,
            seq=seq,
            ack=ack,
            data_offset=data_offset,
            flags=flags,
            window=window,
            checksum=checksum,
            urgent=urgent,
            length=max(0, parsed.total_len - l4_offset),
        )
        parsed.payload_offset = l4_offset + header_len
        parsed.payload_length = max(0, parsed.total_len - (l4_offset + header_len))
    elif protocol == socket.IPPROTO_UDP:
        if len(data) < l4_offset + 8:
            return
        sport = int.from_bytes(data[l4_offset : l4_offset + 2], "big")
        dport = int.from_bytes(data[l4_offset + 2 : l4_offset + 4], "big")
        length = int.from_bytes(data[l4_offset + 4 : l4_offset + 6], "big")
        checksum = int.from_bytes(data[l4_offset + 6 : l4_offset + 8], "big")
        parsed.udp = UDPHeader(
            sport=sport,
            dport=dport,
            length=length,
            checksum=checksum,
        )
        parsed.payload_offset = l4_offset + 8
        parsed.payload_length = max(0, length - 8)
    elif protocol == socket.IPPROTO_ICMP or protocol == 58:  # ICMPv6 = 58
        if len(data) < l4_offset + 4:
            return
        parsed.icmp = ICMPHeader(
            type=data[l4_offset],
            code=data[l4_offset + 1],
            checksum=int.from_bytes(data[l4_offset + 2 : l4_offset + 4], "big"),
        )
        parsed.payload_offset = l4_offset + 4
        parsed.payload_length = max(0, parsed.total_len - (l4_offset + 4))


# ---------------------------------------------------------------------------
# Rebuild + checksums
# ---------------------------------------------------------------------------


def rebuild_packet(parsed: ParsedPacket, *, new_payload: bytes) -> bytes:
    """Return the packet with ``new_payload`` and checksums recomputed.

    Only IPv4 TCP/UDP + IPv6 TCP/UDP are supported. Fragmented
    packets raise ``ValueError`` — the caller should have refused
    earlier via :attr:`ParsedPacket.is_fragmented`.
    """
    if parsed.is_fragmented:
        raise ValueError("cannot rebuild fragmented packet")
    if parsed.tcp is None and parsed.udp is None:
        raise ValueError("rebuild only supports TCP/UDP payloads")
    raw = bytearray(parsed.raw[: parsed.payload_offset] + new_payload)

    if parsed.ipv4 is not None:
        new_total = len(raw)
        raw[2:4] = new_total.to_bytes(2, "big")
        # Zero and recompute IPv4 header checksum.
        raw[10:12] = b"\x00\x00"
        hdr_len = parsed.ipv4.ihl * 4
        raw[10:12] = _checksum16(bytes(raw[:hdr_len])).to_bytes(2, "big")

    if parsed.ipv6 is not None:
        new_payload_len = len(raw) - 40
        raw[4:6] = new_payload_len.to_bytes(2, "big")

    if parsed.tcp is not None:
        tcp_hdr_len = parsed.tcp.data_offset * 4
        tcp_start = parsed.l4_offset
        tcp_end = len(raw)
        raw[tcp_start + 16 : tcp_start + 18] = b"\x00\x00"
        tcp_segment = bytes(raw[tcp_start:tcp_end])
        pseudo = _pseudo_header(parsed, len(tcp_segment), socket.IPPROTO_TCP)
        csum = _checksum16(pseudo + tcp_segment)
        raw[tcp_start + 16 : tcp_start + 18] = csum.to_bytes(2, "big")
        _ = tcp_hdr_len  # keep linter quiet

    if parsed.udp is not None:
        udp_start = parsed.l4_offset
        udp_end = len(raw)
        new_udp_len = udp_end - udp_start
        raw[udp_start + 4 : udp_start + 6] = new_udp_len.to_bytes(2, "big")
        raw[udp_start + 6 : udp_start + 8] = b"\x00\x00"
        udp_segment = bytes(raw[udp_start:udp_end])
        pseudo = _pseudo_header(parsed, len(udp_segment), socket.IPPROTO_UDP)
        csum = _checksum16(pseudo + udp_segment)
        if csum == 0:
            csum = 0xFFFF  # UDP 0 means "no checksum", avoid ambiguity
        raw[udp_start + 6 : udp_start + 8] = csum.to_bytes(2, "big")

    return bytes(raw)


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _pseudo_header(parsed: ParsedPacket, l4_len: int, proto: int) -> bytes:
    if parsed.ipv4 is not None:
        src = socket.inet_pton(socket.AF_INET, parsed.ipv4.src)
        dst = socket.inet_pton(socket.AF_INET, parsed.ipv4.dst)
        return src + dst + b"\x00" + bytes([proto]) + l4_len.to_bytes(2, "big")
    assert parsed.ipv6 is not None
    src = socket.inet_pton(socket.AF_INET6, parsed.ipv6.src)
    dst = socket.inet_pton(socket.AF_INET6, parsed.ipv6.dst)
    return src + dst + l4_len.to_bytes(4, "big") + b"\x00\x00\x00" + bytes([proto])
