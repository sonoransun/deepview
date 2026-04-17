"""SSH-dd remote memory acquisition provider.

Opens an SSH channel to ``endpoint.host`` and runs ``sudo dd`` against the
remote memory source (default ``/dev/mem``), streaming stdout into the
local output file. ``paramiko`` is lazy-imported inside :meth:`acquire`
so that importing this module never requires the optional dep.

Backpressure:
    Paramiko's channel window (2 MiB default) caps in-flight bytes from
    the remote side. Locally we fsync every ``FSYNC_EVERY_BYTES`` so the
    kernel page-cache cannot grow without bound on a slow local disk.
    Override the fsync cadence via ``endpoint.extra['fsync_every_bytes']``.
"""
from __future__ import annotations

import os
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

log = get_logger("memory.acquisition.remote.ssh_dd")

FSYNC_EVERY_BYTES = 64 * 1024 * 1024  # 64 MiB


class SSHDDProvider(RemoteAcquisitionProvider):
    """Acquire memory via ``ssh host 'sudo dd if=/dev/mem bs=1M'``.

    The remote source defaults to ``/dev/mem`` but can be overridden by
    setting ``endpoint.extra['source']`` (for example ``/proc/kcore``).
    """

    @classmethod
    def provider_name(cls) -> str:
        return "ssh-dd"

    def transport_name(self) -> str:
        return "ssh"

    def is_available(self) -> bool:
        try:
            import paramiko  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        # Local privilege. Remote command needs sudo but that's supplied via
        # ``sudo dd`` and orthogonal to our local user/root state.
        return PrivilegeLevel.USER

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        try:
            import paramiko
        except ImportError as e:  # pragma: no cover - exercised only when extra missing
            raise AcquisitionError(
                "paramiko is required for ssh-dd remote acquisition "
                "(pip install 'deepview[remote_acquisition]')"
            ) from e

        if self.endpoint.known_hosts is None:
            raise AcquisitionError(
                "ssh-dd refuses to connect without --known-hosts: "
                "TOFU is disabled for security"
            )
        kh_path = Path(self.endpoint.known_hosts)
        if not kh_path.exists():
            raise AcquisitionError(f"known_hosts file does not exist: {kh_path}")

        source = self.endpoint.extra.get("source", "/dev/mem")
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
            "ssh_dd_connect",
            host=self.endpoint.host,
            port=port,
            username=self.endpoint.username,
            source=source,
        )

        client = paramiko.SSHClient()
        client.load_host_keys(str(kh_path))
        # Reject any host whose key isn't already in known_hosts.
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

        size_bytes = 0
        fsync_every = int(
            self.endpoint.extra.get("fsync_every_bytes", FSYNC_EVERY_BYTES)
        )
        bytes_since_sync = 0
        try:
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
            cmd = f"sudo dd if={source} bs=1M 2>/dev/null"
            _, stdout, _ = client.exec_command(cmd)
            chunk_size = 1024 * 1024
            with open(output, "wb") as dst:
                while True:
                    chunk = stdout.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    size_bytes += len(chunk)
                    bytes_since_sync += len(chunk)
                    # Force a flush periodically so the kernel page cache
                    # cannot grow unbounded when the local disk is slower
                    # than the SSH stream.
                    if fsync_every > 0 and bytes_since_sync >= fsync_every:
                        dst.flush()
                        os.fsync(dst.fileno())
                        bytes_since_sync = 0
                    # Unknown total for a device; pass 0 as total.
                    self._emit_progress(size_bytes, 0, stage="stream")
                dst.flush()
                os.fsync(dst.fileno())
        finally:
            try:
                client.close()
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
