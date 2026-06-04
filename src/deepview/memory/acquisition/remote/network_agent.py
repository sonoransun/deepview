"""Remote memory acquisition via a pre-deployed Deep View agent.

Two wire protocols share one public :class:`NetworkAgentProvider` API:

- **gRPC/TLS** (preferred) — the ``DeepViewAgent.Acquire`` server-stream
  defined in ``deepview_agent.proto``. This path is used *only* when both
  :mod:`grpc` and the generated ``deepview_agent_pb2`` /
  ``deepview_agent_pb2_grpc`` stubs import. The generated stubs are not
  committed; build them where ``grpcio-tools`` is present with::

      python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. \\
          deepview_agent.proto

- **Framed-TCP** (interim default + fallback) — a minimal protocol used
  whenever the gRPC stubs are absent: an 8-byte magic + 1-byte version
  handshake, followed by length-prefixed chunks (``!I`` big-endian,
  0 = EOF). TLS is provided by :mod:`ssl` with a CA bundle supplied in
  ``endpoint.tls_ca``.

:meth:`NetworkAgentProvider.acquire` keeps identical behaviour by default
(framed-TCP); it routes to the gRPC path only when
:func:`_grpc_stubs_available` confirms both :mod:`grpc` and the generated
stubs can be imported. The public API — ``provider_name`` /
``transport_name`` / ``acquire`` / the emitted events / the
:class:`AcquisitionResult` shape — is the same on either path.
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
from deepview.utils.hashing import hash_file

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
            import grpc  # type: ignore[import-untyped]  # noqa: F401
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
        # Prefer the real gRPC transport, but ONLY when both grpc and the
        # generated stubs import. Absence of either => framed-TCP fallback,
        # so the default behaviour is unchanged on a core install.
        if _grpc_stubs_available():
            try:
                return self._acquire_grpc(target, output, fmt)
            except _StubsUnavailable:
                # Lost the race / partial stubs: degrade to framed-TCP.
                log.info("network_agent_grpc_unavailable_fallback", host=self.endpoint.host)
        return self._acquire_framed_tcp(target, output, fmt)

    def _acquire_framed_tcp(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat,
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

        self._emit_progress(size_bytes, size_bytes, stage="hashing")
        digest = hash_file(output)
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
            hash_sha256=digest,
        )

    def _acquire_grpc(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat,
    ) -> AcquisitionResult:
        """Acquire over the real gRPC/TLS ``DeepViewAgent.Acquire`` stream.

        Lazily imports :mod:`grpc` and the generated stubs. If the generated
        ``deepview_agent_pb2`` / ``deepview_agent_pb2_grpc`` modules are
        absent, raises :class:`_StubsUnavailable` so :meth:`acquire` falls
        back to the framed-TCP path. The emitted events, SHA256 hashing, and
        :class:`AcquisitionResult` shape match the framed-TCP path exactly.
        """
        try:
            import grpc
        except Exception as exc:  # noqa: BLE001
            raise _StubsUnavailable("grpc is not importable") from exc
        try:
            from deepview.memory.acquisition.remote import (  # type: ignore[attr-defined]
                deepview_agent_pb2 as pb2,
            )
            from deepview.memory.acquisition.remote import (  # type: ignore[attr-defined]
                deepview_agent_pb2_grpc as pb2_grpc,
            )
        except Exception as exc:  # noqa: BLE001
            raise _StubsUnavailable(
                "network-agent: gRPC stubs not generated — run "
                "`python -m grpc_tools.protoc -I. --python_out=. "
                "--grpc_python_out=. deepview_agent.proto` next to "
                "deepview_agent.proto (in "
                "deepview/memory/acquisition/remote/) to enable the gRPC "
                "transport"
            ) from exc

        port = self.endpoint.port or 9443
        target_addr = f"{self.endpoint.host}:{port}"
        start = time.time()

        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )

        ssl_ctx = self._build_ssl_context()
        if ssl_ctx is not None:
            if self.endpoint.tls_ca is None:
                raise AcquisitionError(
                    "network-agent: require_tls=True but no tls_ca file provided — aborting"
                )
            root_certs = Path(self.endpoint.tls_ca).read_bytes()
            creds = grpc.ssl_channel_credentials(root_certificates=root_certs)
            channel = grpc.secure_channel(target_addr, creds)
        else:
            channel = grpc.insecure_channel(target_addr)

        size_bytes = 0
        try:
            stub = pb2_grpc.DeepViewAgentStub(channel)
            request = pb2.AcquireRequest(format=fmt.value)

            log.info("network_agent_grpc_streaming", host=self.endpoint.host, port=port)

            with open(output, "wb") as dst:
                for chunk in stub.Acquire(request):
                    data = chunk.data
                    if not data:
                        continue
                    dst.write(data)
                    size_bytes += len(data)
                    self._emit_progress(size_bytes, 0, stage="stream")
        finally:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass

        self._emit_progress(size_bytes, size_bytes, stage="hashing")
        digest = hash_file(output)
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
            hash_sha256=digest,
        )


class _StubsUnavailable(RuntimeError):
    """Internal signal: grpc and/or generated stubs are not importable.

    Raised inside :meth:`NetworkAgentProvider._acquire_grpc` so that
    :meth:`NetworkAgentProvider.acquire` can cleanly fall back to the
    framed-TCP transport. Not part of the public API.
    """


def _grpc_stubs_available() -> bool:
    """Return ``True`` iff both :mod:`grpc` and the generated stubs import.

    The generated ``deepview_agent_pb2`` / ``deepview_agent_pb2_grpc``
    modules are not committed to the tree; they're built on demand where
    ``grpcio-tools`` is present. When either the runtime or the stubs are
    missing, :meth:`NetworkAgentProvider.acquire` uses the framed-TCP path.
    """
    try:
        import grpc  # noqa: F401

        from deepview.memory.acquisition.remote import (  # type: ignore[attr-defined]  # noqa: F401
            deepview_agent_pb2,
            deepview_agent_pb2_grpc,
        )
    except Exception:  # noqa: BLE001
        return False
    return True


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
