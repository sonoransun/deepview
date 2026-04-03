"""TCP/IP stack reconstruction from memory images.

Extracts network connection state by scanning for kernel data structures:
  - Windows: pool tag scanning for TcpE/TcpL/UdpA endpoint structures
  - Linux: inet_sock structure walking via brute-force signature scanning

References:
    - Volatility netscan plugin
    - Davidoff & Ham, "Network Forensics: Tracking Hackers Through Cyberspace"
    - Windows tcpip.sys pool tags: TcpE (endpoint), TcpL (listener), UdpA (UDP)
    - Linux kernel: struct inet_sock, struct tcp_sock, struct sock
"""
from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deepview.core.logging import get_logger

if TYPE_CHECKING:
    from deepview.interfaces.layer import DataLayer

log = get_logger("memory.network")

# TCP states (common to Windows and Linux)
TCP_STATES = {
    0: "CLOSED",
    1: "LISTEN",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "ESTABLISHED",
    5: "FIN_WAIT1",
    6: "FIN_WAIT2",
    7: "CLOSE_WAIT",
    8: "CLOSING",
    9: "LAST_ACK",
    10: "TIME_WAIT",
    11: "DELETE_TCB",
}

# Windows pool tags (ASCII little-endian representation)
POOL_TAG_TCPE = b"TcpE"  # TCP endpoint
POOL_TAG_TCPL = b"TcpL"  # TCP listener
POOL_TAG_UDPA = b"UdpA"  # UDP endpoint

# Scan granularity
_SCAN_STEP = 4  # Pool tags are 4-byte aligned


@dataclass(slots=True)
class NetworkConnection:
    """A reconstructed network connection from memory."""

    protocol: str  # "tcp" or "udp"
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int
    process_name: str = ""
    source_offset: int = 0
    metadata: dict = field(default_factory=dict)


class TCPStackReconstructor:
    """Reconstruct network connections from a physical memory image.

    Uses pool tag scanning (Windows) or signature-based scanning (Linux)
    to find kernel network data structures.
    """

    def __init__(self, layer: DataLayer):
        self._layer = layer

    def extract_connections(self, os_hint: str = "auto") -> list[NetworkConnection]:
        """Extract all network connections from the memory image.

        Args:
            os_hint: "windows", "linux", or "auto" (tries both).

        Returns:
            List of reconstructed NetworkConnection objects.
        """
        connections: list[NetworkConnection] = []

        if os_hint in ("windows", "auto"):
            connections.extend(self._scan_windows_pool_tags())

        if os_hint in ("linux", "auto") and not connections:
            connections.extend(self._scan_linux_sockets())

        log.info("tcp_reconstruction_complete", count=len(connections))
        return connections

    # ------------------------------------------------------------------
    # Windows: pool tag scanning
    # ------------------------------------------------------------------

    def _scan_windows_pool_tags(self) -> Iterator[NetworkConnection]:
        """Scan for Windows TCP/UDP pool tag structures."""
        start = self._layer.minimum_address
        end = self._layer.maximum_address
        data_size = 4 * 1024 * 1024  # 4 MiB chunks
        overlap = 4096

        pos = start
        while pos < end:
            chunk_end = min(pos + data_size, end)
            try:
                data = self._layer.read(pos, chunk_end - pos, pad=True)
            except Exception:
                pos += data_size - overlap
                continue

            # Search for TCP endpoint pool tags
            yield from self._parse_tcpe_in_chunk(data, pos)
            yield from self._parse_tcpl_in_chunk(data, pos)
            yield from self._parse_udpa_in_chunk(data, pos)

            pos += data_size - overlap

    def _parse_tcpe_in_chunk(
        self, data: bytes, base: int
    ) -> Iterator[NetworkConnection]:
        """Find TcpE (TCP endpoint) pool tags and parse connection info."""
        tag = POOL_TAG_TCPE
        offset = 0
        while True:
            idx = data.find(tag, offset)
            if idx == -1:
                break
            offset = idx + _SCAN_STEP

            conn = self._try_parse_windows_tcp_endpoint(data, idx, base)
            if conn is not None:
                yield conn

    def _parse_tcpl_in_chunk(
        self, data: bytes, base: int
    ) -> Iterator[NetworkConnection]:
        """Find TcpL (TCP listener) pool tags."""
        tag = POOL_TAG_TCPL
        offset = 0
        while True:
            idx = data.find(tag, offset)
            if idx == -1:
                break
            offset = idx + _SCAN_STEP

            conn = self._try_parse_windows_tcp_listener(data, idx, base)
            if conn is not None:
                yield conn

    def _parse_udpa_in_chunk(
        self, data: bytes, base: int
    ) -> Iterator[NetworkConnection]:
        """Find UdpA (UDP endpoint) pool tags."""
        tag = POOL_TAG_UDPA
        offset = 0
        while True:
            idx = data.find(tag, offset)
            if idx == -1:
                break
            offset = idx + _SCAN_STEP

            conn = self._try_parse_windows_udp_endpoint(data, idx, base)
            if conn is not None:
                yield conn

    def _try_parse_windows_tcp_endpoint(
        self, data: bytes, tag_offset: int, base: int
    ) -> NetworkConnection | None:
        """Parse a Windows _TCP_ENDPOINT structure after a TcpE pool tag.

        The structure layout varies by Windows version, but the general
        pattern after the pool header (tag at offset +4 in _POOL_HEADER)
        is:
            +0x018: AddressFamily (USHORT)
            +0x01C: LocalPort (USHORT, big-endian)
            +0x020: RemotePort (USHORT, big-endian)
            +0x038: State (DWORD)
            +0x058: OwningProcess pointer -> _EPROCESS.UniqueProcessId

        These offsets are for Windows 10 x64 and are approximate.
        """
        # Need at least 0x70 bytes after tag for the structure
        struct_start = tag_offset + 0x10  # Skip past pool header
        if struct_start + 0x70 > len(data):
            return None

        try:
            # Address family at +0x18 from structure start
            af = struct.unpack_from("<H", data, struct_start + 0x18)[0]
            if af not in (2, 23):  # AF_INET=2, AF_INET6=23
                return None

            # Ports are stored in network byte order (big-endian)
            local_port = struct.unpack_from(">H", data, struct_start + 0x1C)[0]
            remote_port = struct.unpack_from(">H", data, struct_start + 0x20)[0]

            # Validate ports
            if local_port == 0 and remote_port == 0:
                return None
            if local_port > 65535 or remote_port > 65535:
                return None

            # State
            state_val = struct.unpack_from("<I", data, struct_start + 0x38)[0]
            state = TCP_STATES.get(state_val, f"UNKNOWN({state_val})")

            # Try to read local/remote addresses
            local_addr = self._read_ipv4(data, struct_start + 0x24)
            remote_addr = self._read_ipv4(data, struct_start + 0x28)

            # PID (approximate offset)
            pid = struct.unpack_from("<I", data, struct_start + 0x58)[0]
            if pid > 65535:  # Sanity check
                pid = 0

            return NetworkConnection(
                protocol="tcp",
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                state=state,
                pid=pid,
                source_offset=base + tag_offset,
            )
        except (struct.error, IndexError):
            return None

    def _try_parse_windows_tcp_listener(
        self, data: bytes, tag_offset: int, base: int
    ) -> NetworkConnection | None:
        """Parse a TCP listener (TcpL) — similar structure but LISTEN state."""
        struct_start = tag_offset + 0x10
        if struct_start + 0x40 > len(data):
            return None

        try:
            af = struct.unpack_from("<H", data, struct_start + 0x18)[0]
            if af not in (2, 23):
                return None

            local_port = struct.unpack_from(">H", data, struct_start + 0x1C)[0]
            if local_port == 0 or local_port > 65535:
                return None

            local_addr = self._read_ipv4(data, struct_start + 0x24)
            pid = struct.unpack_from("<I", data, struct_start + 0x38)[0]
            if pid > 65535:
                pid = 0

            return NetworkConnection(
                protocol="tcp",
                local_addr=local_addr,
                local_port=local_port,
                remote_addr="0.0.0.0",
                remote_port=0,
                state="LISTEN",
                pid=pid,
                source_offset=base + tag_offset,
            )
        except (struct.error, IndexError):
            return None

    def _try_parse_windows_udp_endpoint(
        self, data: bytes, tag_offset: int, base: int
    ) -> NetworkConnection | None:
        """Parse a UDP endpoint (UdpA)."""
        struct_start = tag_offset + 0x10
        if struct_start + 0x40 > len(data):
            return None

        try:
            af = struct.unpack_from("<H", data, struct_start + 0x18)[0]
            if af not in (2, 23):
                return None

            local_port = struct.unpack_from(">H", data, struct_start + 0x1C)[0]
            if local_port == 0 or local_port > 65535:
                return None

            local_addr = self._read_ipv4(data, struct_start + 0x24)
            pid = struct.unpack_from("<I", data, struct_start + 0x38)[0]
            if pid > 65535:
                pid = 0

            return NetworkConnection(
                protocol="udp",
                local_addr=local_addr,
                local_port=local_port,
                remote_addr="*",
                remote_port=0,
                state="",
                pid=pid,
                source_offset=base + tag_offset,
            )
        except (struct.error, IndexError):
            return None

    # ------------------------------------------------------------------
    # Linux: signature-based socket scanning
    # ------------------------------------------------------------------

    def _scan_linux_sockets(self) -> Iterator[NetworkConnection]:
        """Scan for Linux inet_sock structures via signature matching.

        inet_sock contains:
            - sk_common.skc_daddr (remote IPv4, __be32)
            - sk_common.skc_rcv_saddr (local IPv4, __be32)
            - sk_common.skc_dport (remote port, __be16)
            - sk_common.skc_num (local port, host byte order)
            - sk_common.skc_family (AF_INET=2, u16)
            - sk_common.skc_state (TCP state, u8)

        Layout offsets vary by kernel version. We scan for plausible
        combinations: AF_INET family field adjacent to valid port/address
        values.
        """
        start = self._layer.minimum_address
        end = self._layer.maximum_address
        data_size = 4 * 1024 * 1024
        overlap = 4096

        pos = start
        while pos < end:
            chunk_end = min(pos + data_size, end)
            try:
                data = self._layer.read(pos, chunk_end - pos, pad=True)
            except Exception:
                pos += data_size - overlap
                continue

            yield from self._find_inet_socks(data, pos)
            pos += data_size - overlap

    def _find_inet_socks(
        self, data: bytes, base: int
    ) -> Iterator[NetworkConnection]:
        """Search for inet_sock-like structures in a data chunk.

        Looks for the pattern: AF_INET (0x0002) as a 16-bit value at
        aligned offsets, with plausible port and address values nearby.
        Typical sk_common layout (kernel 4.x-6.x, x86_64):
            +0x00: skc_daddr (__be32)
            +0x04: skc_rcv_saddr (__be32)
            +0x0C: skc_dport (__be16)
            +0x0E: skc_num (u16, host order)
            +0x10: skc_family (u16)
            +0x12: skc_state (u8)
        """
        # AF_INET as little-endian u16
        pattern = struct.pack("<H", 2)  # AF_INET
        offset = 0

        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            offset = idx + 2

            # skc_family is at some offset within sk_common.
            # We try the layout where family is at +0x10 from the start.
            sk_start = idx - 0x10
            if sk_start < 0 or sk_start + 0x20 > len(data):
                continue

            try:
                daddr_be = struct.unpack_from(">I", data, sk_start + 0x00)[0]
                saddr_be = struct.unpack_from(">I", data, sk_start + 0x04)[0]
                dport_be = struct.unpack_from(">H", data, sk_start + 0x0C)[0]
                sport_host = struct.unpack_from("<H", data, sk_start + 0x0E)[0]
                state = data[sk_start + 0x12]

                # Validate
                if sport_host == 0 and dport_be == 0:
                    continue
                if sport_host > 65535 or dport_be > 65535:
                    continue
                if state > 11:
                    continue

                # Convert addresses
                local_addr = str(ipaddress.IPv4Address(saddr_be))
                remote_addr = str(ipaddress.IPv4Address(daddr_be))

                # Skip obviously invalid entries (broadcast, etc.)
                if saddr_be == 0xFFFFFFFF:
                    continue

                yield NetworkConnection(
                    protocol="tcp",
                    local_addr=local_addr,
                    local_port=sport_host,
                    remote_addr=remote_addr,
                    remote_port=dport_be,
                    state=TCP_STATES.get(state, f"UNKNOWN({state})"),
                    pid=0,  # PID requires walking task_struct
                    source_offset=base + sk_start,
                )
            except (struct.error, IndexError, ValueError):
                continue

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_ipv4(data: bytes, offset: int) -> str:
        """Read a 4-byte IPv4 address in network byte order."""
        raw = struct.unpack_from(">I", data, offset)[0]
        return str(ipaddress.IPv4Address(raw))
