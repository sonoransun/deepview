"""Tests for TCP/IP stack reconstruction from memory."""
from __future__ import annotations

import struct

import pytest

from deepview.core.types import LayerMetadata
from deepview.interfaces.layer import DataLayer
from deepview.memory.network.tcp_reconstruct import (
    POOL_TAG_TCPE,
    POOL_TAG_TCPL,
    POOL_TAG_UDPA,
    NetworkConnection,
    TCPStackReconstructor,
)


class FakeLayer(DataLayer):
    """In-memory DataLayer for testing."""

    def __init__(self, data: bytes):
        self._data = bytearray(data)

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        end = offset + length
        if end > len(self._data):
            if pad:
                return bytes(self._data[offset:]) + b"\x00" * (end - len(self._data))
            raise ValueError("read beyond end")
        return bytes(self._data[offset:end])

    def write(self, offset: int, data: bytes) -> None:
        self._data[offset : offset + len(data)] = data

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and (offset + length) <= len(self._data)

    def scan(self, scanner, progress_callback=None):
        yield from []

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        return len(self._data)

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(name="fake")


def _build_windows_tcp_endpoint(
    local_ip: tuple[int, int, int, int],
    local_port: int,
    remote_ip: tuple[int, int, int, int],
    remote_port: int,
    state: int,
    pid: int,
) -> bytes:
    """Build a synthetic Windows TcpE pool-tagged structure.

    Layout: pool tag at offset 0, structure starts at +0x10.
    """
    buf = bytearray(0x80)
    # Pool tag at offset 0
    buf[0:4] = POOL_TAG_TCPE
    # Structure starts at +0x10
    struct_off = 0x10
    # AF_INET at +0x18
    struct.pack_into("<H", buf, struct_off + 0x18, 2)
    # Local port (big-endian) at +0x1C
    struct.pack_into(">H", buf, struct_off + 0x1C, local_port)
    # Remote port (big-endian) at +0x20
    struct.pack_into(">H", buf, struct_off + 0x20, remote_port)
    # Local IP at +0x24 (big-endian)
    struct.pack_into(">BBBB", buf, struct_off + 0x24, *local_ip)
    # Remote IP at +0x28 (big-endian)
    struct.pack_into(">BBBB", buf, struct_off + 0x28, *remote_ip)
    # State at +0x38
    struct.pack_into("<I", buf, struct_off + 0x38, state)
    # PID at +0x58
    struct.pack_into("<I", buf, struct_off + 0x58, pid)
    return bytes(buf)


def _build_windows_udp_endpoint(
    local_ip: tuple[int, int, int, int],
    local_port: int,
    pid: int,
) -> bytes:
    """Build a synthetic UdpA pool-tagged structure."""
    buf = bytearray(0x60)
    buf[0:4] = POOL_TAG_UDPA
    struct_off = 0x10
    struct.pack_into("<H", buf, struct_off + 0x18, 2)
    struct.pack_into(">H", buf, struct_off + 0x1C, local_port)
    struct.pack_into(">BBBB", buf, struct_off + 0x24, *local_ip)
    struct.pack_into("<I", buf, struct_off + 0x38, pid)
    return bytes(buf)


class TestNetworkConnection:
    def test_dataclass_fields(self):
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="192.168.1.1",
            local_port=80,
            remote_addr="10.0.0.1",
            remote_port=12345,
            state="ESTABLISHED",
            pid=1234,
        )
        assert conn.protocol == "tcp"
        assert conn.local_port == 80
        assert conn.pid == 1234


class TestWindowsPoolTagScanning:
    def test_find_tcp_endpoint(self):
        padding = b"\x00" * 256
        endpoint = _build_windows_tcp_endpoint(
            local_ip=(192, 168, 1, 100),
            local_port=443,
            remote_ip=(10, 0, 0, 1),
            remote_port=54321,
            state=4,  # ESTABLISHED
            pid=1234,
        )
        data = padding + endpoint + padding
        layer = FakeLayer(data)
        recon = TCPStackReconstructor(layer)

        connections = recon.extract_connections(os_hint="windows")
        assert len(connections) >= 1

        conn = connections[0]
        assert conn.protocol == "tcp"
        assert conn.local_port == 443
        assert conn.remote_port == 54321
        assert conn.state == "ESTABLISHED"
        assert conn.pid == 1234
        assert conn.local_addr == "192.168.1.100"
        assert conn.remote_addr == "10.0.0.1"

    def test_find_udp_endpoint(self):
        padding = b"\x00" * 256
        endpoint = _build_windows_udp_endpoint(
            local_ip=(0, 0, 0, 0),
            local_port=53,
            pid=500,
        )
        data = padding + endpoint + padding
        layer = FakeLayer(data)
        recon = TCPStackReconstructor(layer)

        connections = recon.extract_connections(os_hint="windows")
        udp_conns = [c for c in connections if c.protocol == "udp"]
        assert len(udp_conns) >= 1
        assert udp_conns[0].local_port == 53
        assert udp_conns[0].pid == 500

    def test_multiple_endpoints(self):
        padding = b"\x00" * 256
        ep1 = _build_windows_tcp_endpoint(
            (127, 0, 0, 1), 80, (127, 0, 0, 1), 12345, 4, 100
        )
        ep2 = _build_windows_tcp_endpoint(
            (192, 168, 1, 1), 443, (10, 0, 0, 2), 54321, 4, 200
        )
        data = padding + ep1 + padding + ep2 + padding
        layer = FakeLayer(data)
        recon = TCPStackReconstructor(layer)

        connections = recon.extract_connections(os_hint="windows")
        assert len(connections) >= 2

    def test_invalid_af_ignored(self):
        """Structures with non-AF_INET family should be skipped."""
        buf = bytearray(0x80)
        buf[0:4] = POOL_TAG_TCPE
        # Set AF to 99 (invalid)
        struct.pack_into("<H", buf, 0x10 + 0x18, 99)
        struct.pack_into(">H", buf, 0x10 + 0x1C, 80)
        struct.pack_into(">H", buf, 0x10 + 0x20, 12345)

        data = b"\x00" * 256 + bytes(buf) + b"\x00" * 256
        layer = FakeLayer(data)
        recon = TCPStackReconstructor(layer)

        connections = recon.extract_connections(os_hint="windows")
        # Should not find the invalid entry
        tcp_conns = [c for c in connections if c.local_port == 80]
        assert len(tcp_conns) == 0

    def test_no_connections_in_empty_memory(self):
        data = b"\x00" * 4096
        layer = FakeLayer(data)
        recon = TCPStackReconstructor(layer)
        connections = recon.extract_connections(os_hint="windows")
        assert len(connections) == 0


class TestLinuxSocketScanning:
    def _build_linux_inet_sock(
        self,
        daddr: tuple[int, int, int, int],
        saddr: tuple[int, int, int, int],
        dport: int,
        sport: int,
        state: int,
    ) -> bytes:
        """Build a synthetic Linux inet_sock structure.

        Layout:
            +0x00: skc_daddr (big-endian u32)
            +0x04: skc_rcv_saddr (big-endian u32)
            +0x0C: skc_dport (big-endian u16)
            +0x0E: skc_num (host-order u16)
            +0x10: skc_family (u16, AF_INET=2)
            +0x12: skc_state (u8)
        """
        buf = bytearray(0x30)
        struct.pack_into(">BBBB", buf, 0x00, *daddr)
        struct.pack_into(">BBBB", buf, 0x04, *saddr)
        struct.pack_into(">H", buf, 0x0C, dport)
        struct.pack_into("<H", buf, 0x0E, sport)
        struct.pack_into("<H", buf, 0x10, 2)  # AF_INET
        buf[0x12] = state
        return bytes(buf)

    def test_find_linux_socket(self):
        padding = b"\x00" * 256
        sock = self._build_linux_inet_sock(
            daddr=(10, 0, 0, 1),
            saddr=(192, 168, 1, 100),
            dport=443,
            sport=54321,
            state=4,  # ESTABLISHED
        )
        data = padding + sock + padding
        layer = FakeLayer(data)
        recon = TCPStackReconstructor(layer)

        connections = recon.extract_connections(os_hint="linux")
        # May find additional false positives from AF_INET patterns,
        # but our planted socket should be among them
        matching = [
            c for c in connections
            if c.local_port == 54321 and c.remote_port == 443
        ]
        assert len(matching) >= 1
        conn = matching[0]
        assert conn.state == "ESTABLISHED"
        assert conn.local_addr == "192.168.1.100"
        assert conn.remote_addr == "10.0.0.1"
