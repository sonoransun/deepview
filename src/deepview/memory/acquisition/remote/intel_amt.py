"""Intel AMT acquisition provider (slice 21).

Drives an Intel Active Management Technology (vPro) endpoint over
WS-MAN / HTTPS. Uses stdlib ``urllib`` + ``http.client`` for the HTTP
transport so the module stays importable without any optional
dependencies; if ``requests`` is available it is preferred for its
built-in Digest auth handler. Both paths speak the same SOAP/WS-MAN
envelope.

Important limitation
--------------------
**AMT does not expose host RAM directly.** What AMT provides is:

- Serial-over-LAN (SOL) — a virtual serial console that reads the host
  BIOS/OS output when the host is configured to redirect its serial
  port. We can *record* that stream, but we cannot drive it to dump
  host RAM without operator-supplied tooling on the host.
- KVM — virtual keyboard / video / mouse, useful for interactive
  response but not scriptable for acquisition.
- IDE-Redirection (IDE-R) — present a remote ISO to the host as a
  bootable device. Paired with a custom acquisition ISO this is the
  *only* AMT path that actually approximates "memory imaging": the
  operator supplies an ISO containing e.g. LiME + a post-collection
  transport, AMT changes the boot order, and the host boots into the
  forensic environment.
- Storage-Redirection / USB-R — newer (AMT 11+) equivalent of IDE-R.

Because of this, :class:`IntelAMTProvider` offers two acquisition modes
selected via ``endpoint.extra['mode']``:

``"sol"`` (default)
    Opens an SOL redirection session and records the serial stream
    into ``output`` for ``endpoint.extra['duration_s']`` seconds (or
    until the session is closed by the remote). Useful when the
    operator has already placed a tool on the host that emits an
    acquisition stream (e.g. ``dd`` output) on the serial port.

``"ide-redirect"``
    Issues the WS-MAN ``CIM_BootConfigSetting`` + ``CIM_BootService``
    sequence to change the boot order to the URL supplied via
    ``endpoint.extra['iso_url']`` and reboots the host. The operator
    is responsible for ensuring the ISO runs a tool that streams
    memory somewhere the provider can collect it (typically via a
    companion :class:`TCPStreamProvider` or ``ssh-dd`` run after the
    host comes back up). The ``output`` file in this mode contains a
    JSON status manifest, **not** the memory image itself.

Marked :class:`PrivilegeLevel.USER` because no local privilege is
required; AMT authenticates its own session over HTTPS.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import time
from html import escape as _xml_escape
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlparse

if TYPE_CHECKING:
    from deepview.core.context import AnalysisContext
    from deepview.memory.acquisition.remote.base import RemoteEndpoint

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

log = get_logger("memory.acquisition.remote.intel_amt")


_SHA256_CHUNK = 1 << 20
_WSMAN_NS = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
_SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
_ADDR_NS = "http://schemas.xmlsoap.org/ws/2004/08/addressing"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_SHA256_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _envelope(action: str, resource_uri: str, to: str, body: str) -> str:
    """Construct a minimal WS-MAN SOAP 1.2 envelope."""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{_SOAP_NS}" xmlns:a="{_ADDR_NS}" xmlns:w="{_WSMAN_NS}">'
        f"<s:Header>"
        f"<a:Action>{action}</a:Action>"
        f"<a:To>{to}</a:To>"
        f"<w:ResourceURI>{resource_uri}</w:ResourceURI>"
        f"<a:MessageID>uuid:deepview-amt</a:MessageID>"
        f'<a:ReplyTo><a:Address>'
        f"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        f"</a:Address></a:ReplyTo>"
        f"</s:Header>"
        f"<s:Body>{body}</s:Body>"
        f"</s:Envelope>"
    )


class IntelAMTProvider(RemoteAcquisitionProvider):
    """Intel AMT WS-MAN acquisition provider.

    Modes:

    - ``endpoint.extra['mode'] = 'sol'`` (default): record Serial-
      over-LAN traffic into ``output`` for ``duration_s`` seconds.
    - ``endpoint.extra['mode'] = 'ide-redirect'``: trigger a remote ISO
      boot via WS-MAN and write a JSON status manifest to ``output``.

    Tests and operators that need to bypass the built-in SOL transport
    (for example to mock it or to drive SOL via ``amt-tools``) can set
    :attr:`sol_connector` on the instance: a ``callable(host, port,
    username, password, duration_s) -> bytes`` returning the recorded
    stream. When set, it replaces the default TCP/TLS recorder.
    Similarly, :attr:`wsman_poster` can override the WS-MAN POST
    transport for unit tests.
    """

    sol_connector: Callable[[str, int, str, str, float], bytes] | None = None
    wsman_poster: Callable[..., bytes] | None = None

    def __init__(
        self,
        endpoint: RemoteEndpoint,
        *,
        context: AnalysisContext,
    ) -> None:
        super().__init__(endpoint, context=context)
        # Instance-level overrides default to None; tests assign directly.
        self.sol_connector = None
        self.wsman_poster = None

    @classmethod
    def provider_name(cls) -> str:
        return "intel-amt"

    def transport_name(self) -> str:
        return "amt"

    def is_available(self) -> bool:
        # Stdlib-only fallback is always usable.
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.USER

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    def _resolve_password(self) -> str:
        """Resolve the AMT password from ``endpoint.password_env``.

        Raises :class:`RuntimeError` if the env var is declared but
        empty / unset, or if no env var is configured at all. AMT
        requires a password for Digest auth; there is no "anonymous"
        access and silent downgrade would be a credentials-exposure
        hazard.
        """
        if self.endpoint.password_env is None:
            raise RuntimeError(
                "Intel AMT requires endpoint.password_env pointing at the "
                "env-var holding the AMT admin credentials"
            )
        pw = os.environ.get(self.endpoint.password_env)
        if not pw:
            raise RuntimeError(
                f"Intel AMT password env var '{self.endpoint.password_env}' is "
                "empty or unset; refusing to proceed without credentials"
            )
        return pw

    # ------------------------------------------------------------------
    # Acquire dispatcher
    # ------------------------------------------------------------------

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        mode = self.endpoint.extra.get("mode", "sol")
        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )
        log.info("amt_acquire_begin", host=self.endpoint.host, mode=mode)

        try:
            # Resolve credentials up-front so we fail fast before any
            # network I/O; the failed-completion event is still emitted
            # by the surrounding except clause.
            password = self._resolve_password()
            username = self.endpoint.username or "admin"
            if mode == "sol":
                size_bytes = self._acquire_sol(output, username, password)
            elif mode == "ide-redirect":
                size_bytes = self._acquire_ide_redirect(output, username, password)
            else:
                raise AcquisitionError(
                    f"unknown AMT acquisition mode: {mode!r} "
                    "(expected 'sol' or 'ide-redirect')"
                )
        except Exception as e:  # noqa: BLE001
            log.error("amt_acquire_failed", host=self.endpoint.host, mode=mode, error=str(e))
            elapsed = time.time() - start
            self._context.events.publish(
                RemoteAcquisitionCompletedEvent(
                    endpoint=self.endpoint.host,
                    output=str(output),
                    size_bytes=0,
                    elapsed_s=elapsed,
                )
            )
            raise

        elapsed = time.time() - start
        digest = _sha256_file(output) if output.exists() else ""
        self._context.events.publish(
            RemoteAcquisitionCompletedEvent(
                endpoint=self.endpoint.host,
                output=str(output),
                size_bytes=size_bytes,
                elapsed_s=elapsed,
            )
        )
        log.info(
            "amt_acquire_done",
            host=self.endpoint.host,
            mode=mode,
            size_bytes=size_bytes,
            elapsed_s=elapsed,
        )
        return AcquisitionResult(
            success=True,
            output_path=output,
            format=fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
            hash_sha256=digest,
        )

    # ------------------------------------------------------------------
    # HTTP/WS-MAN plumbing
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        port = self.endpoint.port or 16993
        scheme = "https" if self.endpoint.require_tls else "http"
        return f"{scheme}://{self.endpoint.host}:{port}"

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.endpoint.require_tls:
            return None
        ctx = ssl.create_default_context()
        if self.endpoint.tls_ca is not None:
            ctx.load_verify_locations(cafile=str(self.endpoint.tls_ca))
        return ctx

    def _wsman_post(
        self,
        *,
        username: str,
        password: str,
        action: str,
        resource_uri: str,
        body_xml: str,
    ) -> bytes:
        """POST a WS-MAN envelope using Digest auth. Preferred path is
        ``requests`` (lazy-imported); fallback is stdlib ``urllib`` +
        manual Digest negotiation.
        """
        base = self._base_url()
        url = f"{base}/wsman"
        envelope = _envelope(action, resource_uri, url, body_xml)
        log.info(
            "amt_wsman_post",
            host=self.endpoint.host,
            action=action,
            resource_uri=resource_uri,
            url=url,
        )
        if self.wsman_poster is not None:
            return self.wsman_poster(
                url=url,
                envelope=envelope,
                username=username,
                password=password,
                action=action,
                resource_uri=resource_uri,
            )
        try:
            import requests  # type: ignore[import-untyped]
            from requests.auth import HTTPDigestAuth  # type: ignore[import-untyped]

            resp = requests.post(
                url,
                data=envelope.encode("utf-8"),
                headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                auth=HTTPDigestAuth(username, password),
                verify=(
                    str(self.endpoint.tls_ca)
                    if self.endpoint.tls_ca is not None
                    else self.endpoint.require_tls
                ),
                timeout=30,
            )
            resp.raise_for_status()
            return bytes(resp.content)
        except ImportError:
            return self._wsman_post_urllib(
                url=url,
                envelope=envelope,
                username=username,
                password=password,
            )

    def _wsman_post_urllib(
        self,
        *,
        url: str,
        envelope: str,
        username: str,
        password: str,
    ) -> bytes:
        """Stdlib-only WS-MAN POST with Digest auth negotiation."""
        import urllib.request

        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, url, username, password)
        handlers: list[Any] = [urllib.request.HTTPDigestAuthHandler(mgr)]
        if self.endpoint.require_tls:
            ctx = self._ssl_context()
            if ctx is not None:
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(
            url,
            data=envelope.encode("utf-8"),
            headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
            method="POST",
        )
        with opener.open(req, timeout=30) as resp:
            return bytes(resp.read())

    # ------------------------------------------------------------------
    # Mode 1: Serial-over-LAN recording
    # ------------------------------------------------------------------

    def _acquire_sol(self, output: Path, username: str, password: str) -> int:
        """Record the AMT SOL stream into ``output`` for ``duration_s`` seconds.

        This uses the simplified SOL-over-HTTPS framing that AMT exposes
        on port 16995/tcp. When the ``extra['sol_connector']`` hook is
        supplied (for tests), we delegate the raw byte stream to it so
        unit tests don't need a real AMT listener.
        """
        duration_s = float(self.endpoint.extra.get("duration_s", "30") or "30")
        # Announce the session via WS-MAN; failure here is logged but does not
        # abort SOL collection because some AMT releases gate the enablement
        # endpoint behind per-user ACLs.
        try:
            self._wsman_post(
                username=username,
                password=password,
                action=(
                    "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
                    "CIM_Service/RequestStateChange"
                ),
                resource_uri=(
                    "http://intel.com/wbem/wscim/1/amt-schema/1/"
                    "AMT_RedirectionService"
                ),
                body_xml="<n:RequestStateChange_INPUT xmlns:n=\"http://intel.com/"
                "wbem/wscim/1/amt-schema/1/AMT_RedirectionService\">"
                "<n:RequestedState>32771</n:RequestedState>"
                "</n:RequestStateChange_INPUT>",
            )
        except Exception as e:  # noqa: BLE001
            log.warning("amt_sol_enable_failed", error=str(e))

        sol_port = int(self.endpoint.extra.get("sol_port", "16995") or "16995")

        if self.sol_connector is not None:
            stream = self.sol_connector(
                self.endpoint.host, sol_port, username, password, duration_s
            )
            output.write_bytes(stream)
            self._emit_progress(len(stream), len(stream), stage="sol")
            return len(stream)

        return self._sol_record_stream(
            host=self.endpoint.host,
            port=sol_port,
            username=username,
            password=password,
            duration_s=duration_s,
            output=output,
        )

    def _sol_record_stream(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        duration_s: float,
        output: Path,
    ) -> int:
        """Record raw bytes from the AMT SOL TCP channel into ``output``.

        Note: AMT's real SOL framing is binary and encapsulated inside a
        redirection protocol (APF). A full client implementation is
        outside this provider's scope. For the lab/test path we simply
        open a TCP (optionally TLS) connection after an HTTP Basic
        handshake and record whatever bytes arrive — which is what
        virtually all operator-side AMT SOL dumpers do in practice. The
        output is therefore "best-effort serial log", not a normalized
        stream.
        """
        end = time.time() + duration_s
        total = 0
        raw = socket.create_connection((host, port), timeout=10)
        sock: Any = raw
        try:
            if self.endpoint.require_tls:
                ctx = self._ssl_context()
                assert ctx is not None
                sock = ctx.wrap_socket(raw, server_hostname=host)
            # Best-effort HTTP Basic preamble. Real AMT SOL wants APF;
            # tests inject a ``sol_connector`` instead so this branch is
            # documentation + a sane default for live use.
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
                "ascii"
            )
            preamble = (
                "POST /sol HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Basic {token}\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
            )
            sock.sendall(preamble.encode("ascii"))
            sock.settimeout(2.0)
            with output.open("wb") as fh:
                while time.time() < end:
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        self._emit_progress(total, 0, stage="sol")
                        continue
                    if not chunk:
                        break
                    fh.write(chunk)
                    total += len(chunk)
                    self._emit_progress(total, 0, stage="sol")
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
        self._emit_progress(total, total, stage="sol")
        return total

    # ------------------------------------------------------------------
    # Mode 2: IDE-Redirection boot
    # ------------------------------------------------------------------

    def _acquire_ide_redirect(
        self, output: Path, username: str, password: str
    ) -> int:
        """Trigger a remote-ISO boot via WS-MAN and write a status manifest.

        The ISO URL comes from ``endpoint.extra['iso_url']``. The
        provider issues two WS-MAN operations:

        1. ``CIM_BootSourceSetting`` / ``Put`` — set the boot source
           to the remote ISO. AMT expects an HTTP(S) URL reachable
           from the managed host's AMT controller.
        2. ``CIM_BootService`` / ``RequestStateChange`` — reboot the
           host into the new boot source.

        The manifest is a JSON object summarising the attempt so the
        caller can chain subsequent acquisition steps once the host
        has rebooted into the operator-supplied forensic environment.
        """
        iso_url = self.endpoint.extra.get("iso_url")
        if not iso_url:
            raise AcquisitionError(
                "AMT ide-redirect mode requires endpoint.extra['iso_url']"
            )
        parsed = urlparse(iso_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise AcquisitionError(
                f"AMT ide-redirect: iso_url must be an http(s) URL, got {iso_url!r}"
            )

        # Set the boot source. The ISO URL is XML-escaped defensively.
        escaped_iso = _xml_escape(iso_url, quote=True)
        set_body = (
            '<n:BootSourceSetting xmlns:n="http://schemas.dmtf.org/wbem/wscim/1/'
            'cim-schema/2/CIM_BootSourceSetting">'
            f"<n:StructuredBootString>CIM:Hard-Disk:{escaped_iso}</n:StructuredBootString>"
            "</n:BootSourceSetting>"
        )
        self._wsman_post(
            username=username,
            password=password,
            action=(
                "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
            ),
            resource_uri=(
                "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
                "CIM_BootSourceSetting"
            ),
            body_xml=set_body,
        )
        self._emit_progress(1, 3, stage="ide-redirect:set-boot")

        # Request state change -> reboot into new source (Enabled = 2).
        reboot_body = (
            '<n:RequestStateChange_INPUT xmlns:n="http://schemas.dmtf.org/'
            'wbem/wscim/1/cim-schema/2/CIM_BootService">'
            "<n:RequestedState>2</n:RequestedState>"
            "</n:RequestStateChange_INPUT>"
        )
        self._wsman_post(
            username=username,
            password=password,
            action=(
                "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
                "CIM_BootService/RequestStateChange"
            ),
            resource_uri=(
                "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
                "CIM_BootService"
            ),
            body_xml=reboot_body,
        )
        self._emit_progress(2, 3, stage="ide-redirect:reboot")

        manifest: dict[str, Any] = {
            "host": self.endpoint.host,
            "mode": "ide-redirect",
            "iso_url": iso_url,
            "note": (
                "AMT was instructed to boot from the remote ISO. The host is "
                "rebooting. Collection of the resulting memory image is the "
                "operator's responsibility (typically via a companion "
                "TCPStreamProvider or ssh-dd after the host returns)."
            ),
            "timestamp": time.time(),
        }
        payload = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
        output.write_bytes(payload)
        self._emit_progress(3, 3, stage="ide-redirect:manifest")
        return len(payload)
