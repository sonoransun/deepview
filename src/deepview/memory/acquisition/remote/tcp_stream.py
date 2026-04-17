"""Passive TCP/UDP stream remote acquisition providers.

These providers bind a listener (respectively ``SOCK_STREAM`` and
``SOCK_DGRAM``) on ``endpoint.port`` and accept a single external
streamer (for example a remote ``lime`` insmod with
``path=tcp:<port>``). Bytes are written to ``output`` until the remote
side closes. Format is inferred from magic bytes read at the head of
the stream: LiME ``EMiL`` -> :class:`~DumpFormat.LIME`, ELF ``\\x7fELF``
-> :class:`~DumpFormat.ELF_CORE`, anything else -> :class:`~DumpFormat.RAW`.

Stdlib-only; no external dependencies.
"""
from __future__ import annotations

import socket
import time
from pathlib import Path

from deepview.core.events import (
    RemoteAcquisitionCompletedEvent,
    RemoteAcquisitionStartedEvent,
)
from deepview.core.logging import get_logger
from deepview.core.types import (
    AcquisitionResult,
    AcquisitionTarget,
    DumpFormat,
    Platform,
    PrivilegeLevel,
)
from deepview.memory.acquisition.remote.base import RemoteAcquisitionProvider

log = get_logger("memory.acquisition.remote.tcp_stream")


_LIME_MAGIC = b"EMiL"
_ELF_MAGIC = b"\x7fELF"
_MAGIC_LEN = 4


def _infer_format(head: bytes, requested: DumpFormat) -> DumpFormat:
    """Pick the best DumpFormat given the first few bytes of the stream."""
    if head.startswith(_LIME_MAGIC):
        return DumpFormat.LIME
    if head.startswith(_ELF_MAGIC):
        return DumpFormat.ELF_CORE
    return requested if requested is not DumpFormat.RAW else DumpFormat.RAW


class TCPStreamProvider(RemoteAcquisitionProvider):
    """Bind a TCP listener, accept one connection, stream to disk."""

    @classmethod
    def provider_name(cls) -> str:
        return "tcp-stream"

    def transport_name(self) -> str:
        return "tcp"

    def is_available(self) -> bool:
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.USER

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        bind_host = self.endpoint.extra.get("bind", "0.0.0.0")
        port = self.endpoint.port or 0

        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((bind_host, port))
            srv.listen(1)
            bound_port = srv.getsockname()[1]
            log.info(
                "tcp_stream_listening",
                bind=bind_host,
                port=bound_port,
                expected_peer=self.endpoint.host,
            )
            conn, peer = srv.accept()
        finally:
            srv.close()

        size_bytes = 0
        head = b""
        detected_fmt = fmt
        try:
            with conn, open(output, "wb") as dst:
                conn.settimeout(30.0)
                while len(head) < _MAGIC_LEN:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                if head:
                    detected_fmt = _infer_format(head[:_MAGIC_LEN], fmt)
                    dst.write(head)
                    size_bytes += len(head)
                    self._emit_progress(size_bytes, 0, stage="stream")
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    size_bytes += len(chunk)
                    if size_bytes % (1024 * 1024) < 65536:
                        self._emit_progress(size_bytes, 0, stage="stream")
        except socket.timeout:
            log.warning("tcp_stream_timeout", bytes=size_bytes, peer=str(peer))

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
            format=detected_fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )


class UDPStreamProvider(RemoteAcquisitionProvider):
    """Bind a UDP socket and accept datagrams from ``endpoint.host`` only.

    Because UDP is connection-less we filter on source address; datagrams
    from any other peer are discarded. The stream ends when no packet
    arrives within the receive timeout window.
    """

    @classmethod
    def provider_name(cls) -> str:
        return "udp-stream"

    def transport_name(self) -> str:
        return "udp"

    def is_available(self) -> bool:
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.USER

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        bind_host = self.endpoint.extra.get("bind", "0.0.0.0")
        port = self.endpoint.port or 0
        idle_s = float(self.endpoint.extra.get("idle_s", "10.0"))

        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )

        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_host, port))
        srv.settimeout(idle_s)
        bound_port = srv.getsockname()[1]
        log.info(
            "udp_stream_listening",
            bind=bind_host,
            port=bound_port,
            source=self.endpoint.host,
        )

        size_bytes = 0
        head = b""
        detected_fmt = fmt
        try:
            with open(output, "wb") as dst:
                while True:
                    try:
                        data, addr = srv.recvfrom(65536)
                    except socket.timeout:
                        break
                    if addr[0] != self.endpoint.host:
                        continue
                    if len(head) < _MAGIC_LEN:
                        head = (head + data)[:_MAGIC_LEN]
                        detected_fmt = _infer_format(head, fmt)
                    dst.write(data)
                    size_bytes += len(data)
                    self._emit_progress(size_bytes, 0, stage="stream")
        finally:
            srv.close()

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
            format=detected_fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )
