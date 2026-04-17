"""Remote LiME acquisition provider.

The operator pre-stages a LiME kernel module (``lime.ko``) on the remote
host that is compatible with its running kernel — Deep View intentionally
does not attempt to build or upload a module because that's a dual-use
kernel-code-loading operation that should remain an explicit, auditable
step performed by the incident responder.

Runtime flow:

1. Open an SSH connection to ``endpoint.host`` (paramiko, lazy-imported).
2. Bind a local TCP socket on a free ephemeral port — this is the sink
   LiME will stream into.
3. Request an SSH **reverse** port-forward so the remote side can
   ``connect`` to a local port on the remote box and have the bytes
   appear on our local listener. (``transport.request_port_forward``.)
4. Execute ``sudo insmod <lime_ko_path> path=tcp:<remote_port> format=lime``
   over SSH. LiME blocks waiting for a client, connects to the forwarded
   port, and starts streaming.
5. Accept the inbound connection on our local listener and copy bytes
   to ``output``, publishing :class:`RemoteAcquisitionProgressEvent` as
   we go.
6. Once the stream closes, ``sudo rmmod lime`` over a second exec
   channel to leave the remote host clean.

Operator responsibilities:

- ``lime.ko`` must exist on the remote host at ``endpoint.extra["lime_ko_path"]``
  (default ``/tmp/lime.ko``) and match the remote kernel.
- The remote account (``endpoint.username``) must have passwordless sudo
  for ``insmod`` / ``rmmod`` or a password supplied via the
  ``password_env`` indirection.
- ``endpoint.known_hosts`` is mandatory — TOFU is disabled for security.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

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

log = get_logger("memory.acquisition.remote.lime_remote")


_DEFAULT_LIME_KO = "/tmp/lime.ko"
_DEFAULT_REMOTE_PORT = 4444
_ACCEPT_TIMEOUT_S = 60.0
_CHUNK_SIZE = 1024 * 1024


def _bridge_channel_to_socket(channel: Any, sink: socket.socket) -> None:
    """Pump bytes from a paramiko forwarded channel into a local socket.

    Paramiko runs this callback on its own dispatch thread. We spin one
    helper thread for the sink->channel direction (never needed for
    LiME, which is one-way) so we can use a blocking read on the
    channel in this thread without starving paramiko.
    """
    def _reverse() -> None:
        try:
            while True:
                data = sink.recv(_CHUNK_SIZE)
                if not data:
                    break
                channel.sendall(data)
        except Exception:  # noqa: BLE001
            pass

    rt = threading.Thread(target=_reverse, daemon=True)
    rt.start()
    try:
        while True:
            data = channel.recv(_CHUNK_SIZE)
            if not data:
                break
            sink.sendall(data)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            channel.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            sink.close()
        except Exception:  # noqa: BLE001
            pass


class LiMERemoteProvider(RemoteAcquisitionProvider):
    """Acquire memory via a pre-staged remote LiME kernel module.

    Uses SSH for control + a reverse TCP tunnel as the data sink.
    """

    @classmethod
    def provider_name(cls) -> str:
        return "remote-lime"

    def transport_name(self) -> str:
        return "lime-remote"

    def is_available(self) -> bool:
        try:
            import paramiko  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        # The *target* must be Linux (LiME is a Linux kernel module); the
        # local side can be anything capable of running paramiko.
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        # Local process does not need privilege; the remote side runs
        # ``sudo insmod`` and supplies its own elevation.
        return PrivilegeLevel.USER

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.LIME,
    ) -> AcquisitionResult:
        try:
            import paramiko
        except ImportError as e:  # pragma: no cover - exercised only when extra missing
            raise AcquisitionError(
                "paramiko is required for remote-lime acquisition "
                "(pip install 'deepview[remote_acquisition]')"
            ) from e

        if self.endpoint.known_hosts is None:
            raise AcquisitionError(
                "remote-lime refuses to connect without --known-hosts: "
                "TOFU is disabled for security"
            )
        kh_path = Path(self.endpoint.known_hosts)
        if not kh_path.exists():
            raise AcquisitionError(f"known_hosts file does not exist: {kh_path}")

        lime_ko_path = self.endpoint.extra.get("lime_ko_path", _DEFAULT_LIME_KO)
        remote_port_raw = self.endpoint.extra.get("remote_lime_port")
        remote_port = int(remote_port_raw) if remote_port_raw is not None else _DEFAULT_REMOTE_PORT
        port = self.endpoint.port or 22

        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )
        log.info(
            "lime_remote_connect",
            host=self.endpoint.host,
            port=port,
            username=self.endpoint.username,
            lime_ko_path=lime_ko_path,
            remote_port=remote_port,
        )

        client = paramiko.SSHClient()
        client.load_host_keys(str(kh_path))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.endpoint.host,
            "port": port,
            "username": self.endpoint.username,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if self.endpoint.identity_file is not None:
            connect_kwargs["key_filename"] = str(self.endpoint.identity_file)
        if self.endpoint.password_env is not None:
            pw = os.environ.get(self.endpoint.password_env)
            if pw:
                connect_kwargs["password"] = pw

        # Local listening socket for the reverse-forwarded stream.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        local_port = listener.getsockname()[1]
        log.info("lime_remote_listener", local_port=local_port)

        size_bytes = 0
        insmod_ran = False
        try:
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
            transport = client.get_transport()
            if transport is None:  # pragma: no cover - paramiko returns a transport
                raise AcquisitionError("remote-lime: SSH transport unavailable after connect")

            # Ask the server to forward inbound connections on its
            # ``remote_port`` back to our local listener. The handler
            # bridges each forwarded channel into a short-lived connection
            # to ``127.0.0.1:local_port`` — exactly the shape ``ssh -R``
            # implements on the command line. LiME only opens one channel,
            # but the handler runs in paramiko's own thread pool so we
            # start a bridging thread to copy bytes both ways without
            # blocking paramiko's dispatch loop.
            def _forward_handler(
                channel: Any, origin: Any, destination: Any
            ) -> None:
                try:
                    sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sink.connect(("127.0.0.1", local_port))
                except OSError as exc:
                    log.warning("lime_remote_bridge_connect_failed", error=str(exc))
                    try:
                        channel.close()
                    except Exception:  # noqa: BLE001
                        pass
                    return
                _bridge_channel_to_socket(channel, sink)

            transport.request_port_forward(
                address="127.0.0.1",
                port=remote_port,
                handler=_forward_handler,
            )

            # Kick off LiME on the far side. ``insmod`` blocks until the
            # sink closes, so exec asynchronously via a new channel.
            insmod_cmd = (
                f"sudo insmod {lime_ko_path} "
                f"path=tcp:{remote_port} format=lime"
            )
            log.info("lime_remote_insmod", cmd=insmod_cmd)
            _, insmod_stdout, _ = client.exec_command(insmod_cmd)
            insmod_ran = True
            # Don't wait for insmod to return here; it only returns when
            # the module is unloaded. We *do* read progressively below.

            # Accept LiME's reverse-forwarded connection.
            listener.settimeout(_ACCEPT_TIMEOUT_S)
            self._emit_progress(0, 0, stage="waiting-for-stream")
            conn, peer = listener.accept()
            log.info("lime_remote_accepted", peer=str(peer))
            conn.settimeout(None)
            try:
                with open(output, "wb") as dst:
                    while True:
                        chunk = conn.recv(_CHUNK_SIZE)
                        if not chunk:
                            break
                        dst.write(chunk)
                        size_bytes += len(chunk)
                        self._emit_progress(size_bytes, 0, stage="stream")
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass

            # Drain insmod's stdout (best-effort; LiME is silent on success).
            try:
                insmod_stdout.channel.recv_exit_status()
            except Exception:  # noqa: BLE001
                pass
        finally:
            # Cleanup: rmmod + close transport. Best-effort: we do not want
            # rmmod failure to mask a successful acquisition.
            try:
                if insmod_ran:
                    log.info("lime_remote_rmmod")
                    _, rmmod_stdout, _ = client.exec_command("sudo rmmod lime")
                    try:
                        rmmod_stdout.channel.recv_exit_status()
                    except Exception:  # noqa: BLE001
                        pass
            except Exception as exc:  # noqa: BLE001
                log.warning("lime_remote_rmmod_failed", error=str(exc))
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                listener.close()
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
        log.info(
            "lime_remote_done",
            host=self.endpoint.host,
            size_bytes=size_bytes,
            elapsed_s=elapsed,
        )
        return AcquisitionResult(
            success=True,
            output_path=output,
            format=fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )
