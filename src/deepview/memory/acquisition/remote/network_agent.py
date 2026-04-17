"""Remote memory acquisition via a pre-deployed Deep View agent.

This is the "interim transport" used until the gRPC stubs are generated
from ``deepview_agent.proto``. We keep the shape of a gRPC client —
lazy-import :mod:`grpc` purely to gate :meth:`is_available` — but the
actual wire is a minimal framed-TCP protocol: an 8-byte magic + 1-byte
version handshake, followed by length-prefixed chunks
(``!I`` big-endian, 0 = EOF). TLS is provided by :mod:`ssl` with a CA
bundle supplied in ``endpoint.tls_ca``.

The framed protocol is intentionally boring: the moment the ``.proto``
and generated stubs land, this file swaps to a proper gRPC client and
the public :class:`NetworkAgentProvider` API stays unchanged.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
from pathlib import Path

from deepview.core.events import (
    RemoteAcquisitionCompletedEvent,
    RemoteAcquisitionStartedEvent,
)
from deepview.core.exceptions import AcquisitionError
from deepview.core.logging import get_logger
from deepview.core.types import (
    AcquisitionResult,
    AcquisitionTarget,
    DumpFormat,
    Platform,
    PrivilegeLevel,
)
from deepview.memory.acquisition.remote.base import RemoteAcquisitionProvider

log = get_logger("memory.acquisition.remote.network_agent")


AGENT_MAGIC = b"DVAGENT\x00"
AGENT_VERSION = 1
_LEN_FMT = "!I"
_LEN_SIZE = struct.calcsize(_LEN_FMT)


class NetworkAgentProvider(RemoteAcquisitionProvider):
    """Client for the Deep View acquisition agent (interim framed-TCP).

    The final version will speak gRPC/TLS. Until the generated stubs land
    we ship this framed protocol so the CLI and tests can exercise the
    path end-to-end.
    """

    @classmethod
    def provider_name(cls) -> str:
        return "network-agent"

    def transport_name(self) -> str:
        return "grpc"

    def is_available(self) -> bool:
        # grpc is the *eventual* transport; not being able to import it is
        # not fatal for the interim framed-TCP path, but the availability
        # check advertises the preferred transport for parity with the
        # other providers' optional-dep gating.
        try:
            import grpc  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.USER

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        if not self.endpoint.require_tls:
            return None
        if self.endpoint.tls_ca is None:
            raise AcquisitionError(
                "network-agent: require_tls=True but no tls_ca file provided — aborting"
            )
        ca_path = Path(self.endpoint.tls_ca)
        if not ca_path.exists():
            raise AcquisitionError(f"network-agent: tls_ca not found: {ca_path}")
        ctx = ssl.create_default_context(cafile=str(ca_path))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        port = self.endpoint.port or 9443
        start = time.time()

        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )

        ctx = self._build_ssl_context()
        raw_sock = socket.create_connection((self.endpoint.host, port), timeout=30.0)
        if ctx is not None:
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=self.endpoint.host)
        else:
            sock = raw_sock

        size_bytes = 0
        try:
            # Handshake: client -> server MAGIC + version.
            sock.sendall(AGENT_MAGIC + bytes([AGENT_VERSION]))
            hello = _recv_exact(sock, len(AGENT_MAGIC) + 1)
            if hello[: len(AGENT_MAGIC)] != AGENT_MAGIC:
                raise AcquisitionError("network-agent: bad handshake magic")
            if hello[-1] != AGENT_VERSION:
                raise AcquisitionError(
                    f"network-agent: protocol version mismatch "
                    f"(server={hello[-1]} client={AGENT_VERSION})"
                )
            # Request: "Acquire" RPC with desired format as 1-byte selector.
            rpc = b"Acquire"
            sock.sendall(struct.pack(_LEN_FMT, len(rpc)))
            sock.sendall(rpc)

            log.info("network_agent_streaming", host=self.endpoint.host, port=port)

            with open(output, "wb") as dst:
                while True:
                    hdr = _recv_exact(sock, _LEN_SIZE)
                    (chunk_len,) = struct.unpack(_LEN_FMT, hdr)
                    if chunk_len == 0:
                        break
                    chunk = _recv_exact(sock, chunk_len)
                    dst.write(chunk)
                    size_bytes += chunk_len
                    self._emit_progress(size_bytes, 0, stage="stream")
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        elapsed = time.time() - start
        self._context.events.publish(
            RemoteAcquisitionCompletedEvent(
                endpoint=self.endpoint.host,
                output=str(output),
                size_bytes=size_bytes,
                elapsed_s=elapsed,
            )
        )
        return AcquisitionResult(
            success=True,
            output_path=output,
            format=fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise :class:`AcquisitionError`."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AcquisitionError(
                f"network-agent: connection closed after {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)
