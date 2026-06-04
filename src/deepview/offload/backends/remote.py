"""Remote-worker offload backend — framed-TCP + JSON.

A pre-deployed ``deepview-worker`` process (see :func:`serve`) consumes
:class:`OffloadJob` payloads over a length-prefixed framed-TCP channel
and replies with the fields of an :class:`OffloadResult`. The wire shape
mirrors :mod:`deepview.memory.acquisition.remote.network_agent` — a
4-byte big-endian (``!I``) length prefix in front of each frame — but the
frame body is a JSON document rather than raw bytes.

Why JSON and not msgpack? The remote backend has to stay stdlib-only so a
core install (no optional deps) can still import this module, run the
loopback worker, and exercise the path under ``pytest``. The earlier plan
to use msgpack-over-TCP with mutual-TLS is still the long-term target;
swapping the codec later will not change the public
:class:`RemoteWorkerBackend` API.

Bytes-over-JSON
---------------
JSON cannot carry raw bytes, but KDF payloads (``password`` / ``salt`` /
``data``) and KDF outputs are bytes. Two conventions bridge that gap:

* request payloads are walked recursively and every ``bytes`` value is
  replaced with ``{"__bytes__": "<hex>"}`` (see :func:`_encode_payload`),
  which the worker reverses via :func:`_decode_payload`;
* the worker hex-encodes the callable's ``bytes`` return value and tags
  it ``output_is_bytes=True`` so the client can ``bytes.fromhex`` it back
  (see :func:`_encode_output` / the client decode in
  :meth:`RemoteWorkerBackend.submit`).

TLS is optional: pass a CA bundle path via ``tls_ca`` to require a
verified server certificate; loopback tests run with TLS disabled.
"""
from __future__ import annotations

import json
import socket
import ssl
import struct
import time
from concurrent.futures import Future
from pathlib import Path

# Reuse the exact resolve/run helpers the thread/process backends use so a
# job executes identically regardless of which backend it lands on.
from deepview.offload.backends.base import OffloadBackend
from deepview.offload.backends.thread import _resolve_callable
from deepview.offload.jobs import OffloadJob, OffloadResult

_LEN_FMT = "!I"
_LEN_SIZE = struct.calcsize(_LEN_FMT)
_MAX_FRAME = 64 * 1024 * 1024  # 64 MiB guard against a hostile/garbled length prefix
_BACKEND_NAME = "remote"


class RemoteProtocolError(RuntimeError):
    """Raised when a framed-TCP frame is malformed or the peer hangs up early."""


# --------------------------------------------------------------------------- #
# Framing helpers (mirror network_agent._recv_exact + a !I length prefix)
# --------------------------------------------------------------------------- #
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise :class:`RemoteProtocolError`."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RemoteProtocolError(
                f"remote: connection closed after {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def _send_frame(sock: socket.socket, obj: object) -> None:
    """JSON-encode *obj* and send it behind a ``!I`` length prefix."""
    body = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(_LEN_FMT, len(body)))
    sock.sendall(body)


def _recv_frame(sock: socket.socket) -> object:
    """Read one length-prefixed JSON frame and decode it."""
    (length,) = struct.unpack(_LEN_FMT, _recv_exact(sock, _LEN_SIZE))
    if length == 0:
        raise RemoteProtocolError("remote: empty frame")
    if length > _MAX_FRAME:
        raise RemoteProtocolError(f"remote: frame too large ({length} bytes)")
    body = _recv_exact(sock, length)
    return json.loads(body.decode("utf-8"))


# --------------------------------------------------------------------------- #
# Bytes <-> JSON helpers
# --------------------------------------------------------------------------- #
def _encode_payload(value: object) -> object:
    """Recursively replace ``bytes`` with ``{"__bytes__": "<hex>"}``.

    Walks dicts and lists so nested payloads (the KDF payload dicts) come
    through with their byte fields intact. Other JSON-native values pass
    through unchanged; non-serialisable values are left for :mod:`json` to
    reject loudly.
    """
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, dict):
        return {k: _encode_payload(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_payload(v) for v in value]
    return value


def _decode_payload(value: object) -> object:
    """Reverse :func:`_encode_payload` — turn ``{"__bytes__": ...}`` back to bytes."""
    if isinstance(value, dict):
        if set(value.keys()) == {"__bytes__"} and isinstance(value["__bytes__"], str):
            return bytes.fromhex(value["__bytes__"])
        return {k: _decode_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_payload(v) for v in value]
    return value


def _encode_output(output: object) -> tuple[object, bool]:
    """Return ``(json_safe_output, output_is_bytes)`` for a callable's return value."""
    if isinstance(output, bytes):
        return output.hex(), True
    return output, False


# --------------------------------------------------------------------------- #
# Reference worker (server side)
# --------------------------------------------------------------------------- #
def _handle_request(request: object) -> dict[str, object]:
    """Resolve + run one request dict, returning a JSON-safe result dict.

    The request shape is ``{job_id, kind, payload, callable_ref}``; the
    callable is resolved and executed with the thread backend's helpers so
    behaviour is identical to the in-process backends. Any failure is
    captured into ``ok=False`` rather than crashing the worker loop.
    """
    if not isinstance(request, dict):
        return {
            "job_id": None,
            "ok": False,
            "output": None,
            "output_is_bytes": False,
            "error": "remote: request must be a JSON object",
            "elapsed_s": 0.0,
        }
    job_id = request.get("job_id")
    callable_ref = request.get("callable_ref")
    payload = _decode_payload(request.get("payload"))
    started = time.perf_counter()
    if not isinstance(callable_ref, str):
        return {
            "job_id": job_id,
            "ok": False,
            "output": None,
            "output_is_bytes": False,
            "error": "callable_ref is required for the remote backend",
            "elapsed_s": time.perf_counter() - started,
        }
    try:
        func = _resolve_callable(callable_ref)
        if not callable(func):
            raise TypeError(f"{callable_ref!r} is not callable")
        output = func(payload)
        json_output, is_bytes = _encode_output(output)
    except BaseException as exc:  # noqa: BLE001 — worker is the error firewall
        return {
            "job_id": job_id,
            "ok": False,
            "output": None,
            "output_is_bytes": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": time.perf_counter() - started,
        }
    return {
        "job_id": job_id,
        "ok": True,
        "output": json_output,
        "output_is_bytes": is_bytes,
        "error": None,
        "elapsed_s": time.perf_counter() - started,
    }


def serve_once(conn: socket.socket) -> None:
    """Read one request frame from *conn*, execute it, and write the result frame."""
    request = _recv_frame(conn)
    response = _handle_request(request)
    _send_frame(conn, response)


def serve(
    host: str,
    port: int,
    *,
    tls_context: ssl.SSLContext | None = None,
    backlog: int = 8,
) -> None:
    """Serve the framed-TCP offload protocol forever (one request per connection).

    Each accepted connection carries a single
    ``{job_id, kind, payload, callable_ref}`` request and receives a single
    result frame, mirroring :meth:`RemoteWorkerBackend.submit`'s
    per-call connection model. Pass *tls_context* (a server-side
    :class:`ssl.SSLContext`) to require TLS. A per-connection failure is
    swallowed so one bad client cannot take the worker down.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(backlog)
    try:
        while True:
            raw_conn, _ = srv.accept()
            conn: socket.socket = raw_conn
            try:
                if tls_context is not None:
                    conn = tls_context.wrap_socket(raw_conn, server_side=True)
                serve_once(conn)
            except Exception:  # noqa: BLE001 — keep the loop alive across bad clients
                pass
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
    finally:
        try:
            srv.close()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# Backend (client side)
# --------------------------------------------------------------------------- #
class RemoteWorkerBackend(OffloadBackend):
    """Framed-TCP + JSON client for a remote ``deepview-worker`` pool.

    Connections are per-call: :meth:`submit` opens a socket, sends one
    request frame, reads one result frame, and closes. The returned future
    is *already resolved* — there is no background pool — which keeps the
    backend a drop-in for the engine's future-based API without owning a
    thread/process pool. :meth:`is_available` is ``True`` only when an
    endpoint was configured, so the engine's default backend selection
    (``process``) is unaffected when this backend is registered without an
    endpoint.
    """

    _NAME = _BACKEND_NAME
    _CAPS: frozenset[str] = frozenset({"remote", "pbkdf2_sha256", "argon2id", "sha512"})

    def __init__(
        self,
        endpoint: str = "",
        *,
        tls_ca: str | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        self._endpoint = endpoint
        self._tls_ca = tls_ca
        self._timeout_s = timeout_s
        self._host, self._port = _parse_endpoint(endpoint)

    @property
    def name(self) -> str:
        return self._NAME

    def capabilities(self) -> set[str]:
        return set(self._CAPS)

    def is_available(self) -> bool:
        # Available only when an endpoint is configured. With no endpoint the
        # backend is inert so registering it never displaces ``process`` as
        # the engine default.
        return bool(self._endpoint) and self._host is not None and self._port is not None

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        if self._tls_ca is None:
            return None
        ca_path = Path(self._tls_ca)
        if not ca_path.exists():
            raise RemoteProtocolError(f"remote: tls_ca not found: {ca_path}")
        ctx = ssl.create_default_context(cafile=str(ca_path))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def submit(self, job: OffloadJob[object, object]) -> Future[OffloadResult]:
        future: Future[OffloadResult] = Future()
        future.set_result(self._run(job))
        return future

    def _run(self, job: OffloadJob[object, object]) -> OffloadResult:
        started = time.perf_counter()
        if self._host is None or self._port is None:
            return OffloadResult(
                job_id=job.job_id,
                ok=False,
                output=None,
                error=f"remote: invalid endpoint {self._endpoint!r} (want 'host:port')",
                elapsed_s=time.perf_counter() - started,
                backend=self._NAME,
            )
        request = {
            "job_id": job.job_id,
            "kind": job.kind,
            "payload": _encode_payload(job.payload),
            "callable_ref": job.callable_ref,
        }
        sock: socket.socket | None = None
        try:
            ctx = self._build_ssl_context()
            raw_sock = socket.create_connection(
                (self._host, self._port), timeout=self._timeout_s
            )
            sock = (
                ctx.wrap_socket(raw_sock, server_hostname=self._host)
                if ctx is not None
                else raw_sock
            )
            _send_frame(sock, request)
            response = _recv_frame(sock)
        except Exception as exc:  # noqa: BLE001 — backend is the error firewall
            return OffloadResult(
                job_id=job.job_id,
                ok=False,
                output=None,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_s=time.perf_counter() - started,
                backend=self._NAME,
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass
        return self._result_from_response(job, response, started)

    def _result_from_response(
        self,
        job: OffloadJob[object, object],
        response: object,
        started: float,
    ) -> OffloadResult:
        if not isinstance(response, dict):
            return OffloadResult(
                job_id=job.job_id,
                ok=False,
                output=None,
                error="remote: malformed response (not a JSON object)",
                elapsed_s=time.perf_counter() - started,
                backend=self._NAME,
            )
        ok = bool(response.get("ok"))
        output = response.get("output")
        if ok and response.get("output_is_bytes") and isinstance(output, str):
            output = bytes.fromhex(output)
        elapsed = response.get("elapsed_s")
        return OffloadResult(
            job_id=job.job_id,
            ok=ok,
            output=output if ok else None,
            error=None if ok else (response.get("error") or "remote: unknown error"),
            elapsed_s=float(elapsed) if isinstance(elapsed, (int, float)) else (
                time.perf_counter() - started
            ),
            backend=self._NAME,
        )

    def shutdown(self, wait: bool = True) -> None:
        # Per-call connections; nothing pooled to tear down.
        return None


def _parse_endpoint(endpoint: str) -> tuple[str | None, int | None]:
    """Parse ``"host:port"`` into ``(host, port)``; ``("", _)`` -> ``(None, None)``."""
    if not endpoint:
        return None, None
    host, sep, port_str = endpoint.rpartition(":")
    if not sep or not host:
        return None, None
    try:
        port = int(port_str)
    except ValueError:
        return None, None
    if not (0 < port < 65536):
        return None, None
    return host, port


__all__ = [
    "RemoteWorkerBackend",
    "RemoteProtocolError",
    "serve",
    "serve_once",
]
