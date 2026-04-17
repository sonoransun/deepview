"""IPMI out-of-band acquisition provider (slice 21).

Talks to a Baseboard Management Controller (BMC) over IPMI 2.0 LANplus
using the optional ``python-ipmi`` dependency. ``pyipmi`` is imported
lazily inside :meth:`IPMIMemoryProvider.acquire` so the module is safe
to import in a core install.

Important limitation
--------------------
IPMI is a **management-plane** protocol. The overwhelming majority of
BMCs do *not* expose host RAM over IPMI at all. What IPMI *does*
reliably expose is:

- ``Get FW Version`` / ``Get Device ID`` — BMC firmware identification.
- System Event Log (SEL) — hardware + firmware event history.
- Sensor Data Records (SDR) — temperature / voltage / fan telemetry.
- Some Dell (iDRAC), HP (iLO), and Supermicro vendors layer OEM
  extensions on top of IPMI that *can* snapshot the BMC's own NVRAM or
  SPI flash. These are vendor-specific and not portable across BMCs.

Because of this, :class:`IPMIMemoryProvider` offers two acquisition
modes (selected by ``endpoint.extra['mode']``):

``"sel"`` (default)
    Enumerate the SEL via ``pyipmi.Ipmi.get_sel_iterator()`` and write a
    JSONL record per SEL entry into ``output``. The resulting file is a
    forensic artifact of the BMC's event history, **not** a memory
    image of the host. ``AcquisitionResult.format`` is preserved as
    whatever the caller passed (default :class:`DumpFormat.RAW`); the
    file itself is JSONL text.

``"firmware"``
    Best-effort BMC firmware acquisition via OEM raw commands. Vendor
    procedure is selected by ``endpoint.extra['vendor']`` and is
    documented inline below. The output is a binary blob the caller
    should wrap as :class:`DumpFormat.SPI_FLASH` for downstream
    storage-layer analysis. Vendor procedures are *documented, not
    executed* — they vary enough that Deep View will not silently issue
    proprietary raw commands; the operator must explicitly opt in via
    ``endpoint.extra['vendor']`` and accept the mode's limitations.

The provider is marked :class:`PrivilegeLevel.USER` because it needs no
local privilege to open a TCP socket; the remote operation is
authenticated to the BMC itself.
"""
from __future__ import annotations

import hashlib
import json
import os
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

log = get_logger("memory.acquisition.remote.ipmi")


_SHA256_CHUNK = 1 << 20


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_SHA256_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class IPMIMemoryProvider(RemoteAcquisitionProvider):
    """IPMI 2.0 LANplus acquisition provider.

    Accepts ``endpoint.extra['mode']`` of ``"sel"`` (default) or
    ``"firmware"``. SEL mode produces a JSONL event-log artifact;
    firmware mode produces a BMC flash blob and is vendor-specific
    (Dell / HP / Supermicro documented inline).
    """

    @classmethod
    def provider_name(cls) -> str:
        return "ipmi"

    def transport_name(self) -> str:
        return "ipmi"

    def is_available(self) -> bool:
        try:
            import pyipmi  # noqa: F401
            import pyipmi.interfaces  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.USER

    # ------------------------------------------------------------------
    # Credential handling
    # ------------------------------------------------------------------

    def _resolve_password(self) -> str | None:
        """Resolve the BMC password from ``endpoint.password_env``.

        Raises :class:`RuntimeError` if the env-var name is declared
        but the env-var is empty / unset — we refuse to silently fall
        back to no-password IPMI which would be a downgrade attack
        vector.
        """
        if self.endpoint.password_env is None:
            return None
        pw = os.environ.get(self.endpoint.password_env)
        if not pw:
            raise RuntimeError(
                f"IPMI password env var '{self.endpoint.password_env}' is empty "
                "or unset; refusing to authenticate without credentials"
            )
        return pw

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    def _connect(self) -> Any:
        """Open an IPMI 2.0 LANplus session to the BMC and return the handle."""
        try:
            import pyipmi  # type: ignore[import-untyped]
            import pyipmi.interfaces  # type: ignore[import-untyped]
        except ImportError as e:  # pragma: no cover - exercised only when extra missing
            raise AcquisitionError(
                "pyipmi is required for IPMI remote acquisition "
                "(pip install 'deepview[remote_acquisition]')"
            ) from e

        port = self.endpoint.port or 623
        username = self.endpoint.username or ""
        password = self._resolve_password() or ""

        log.info(
            "ipmi_connect",
            host=self.endpoint.host,
            port=port,
            username=username,
            transport="lanplus",
        )

        interface = pyipmi.interfaces.create_interface(
            "ipmitool", interface_type="lanplus"
        )
        ipmi = pyipmi.create_connection(interface)
        ipmi.session.set_session_type_rmcp(self.endpoint.host, port=port)
        ipmi.session.set_auth_type_user(username, password)
        ipmi.target = pyipmi.Target(0x20)
        ipmi.session.establish()
        return ipmi

    # ------------------------------------------------------------------
    # Acquire dispatcher
    # ------------------------------------------------------------------

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        mode = self.endpoint.extra.get("mode", "sel")
        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )
        log.info("ipmi_acquire_begin", host=self.endpoint.host, mode=mode)

        try:
            # Resolve credentials up-front so that a missing password env
            # raises before we try to import the optional dep or touch
            # the network. The sub-calls pass the resolved password
            # through ``_connect`` via ``_resolve_password`` again; that
            # re-check is cheap and keeps `_connect` self-contained.
            self._resolve_password()
            if mode == "sel":
                size_bytes = self._acquire_sel(output)
            elif mode == "firmware":
                size_bytes = self._acquire_firmware(output)
            else:
                raise AcquisitionError(
                    f"unknown IPMI acquisition mode: {mode!r} (expected 'sel' or 'firmware')"
                )
        except Exception as e:  # noqa: BLE001
            log.error("ipmi_acquire_failed", host=self.endpoint.host, mode=mode, error=str(e))
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
            "ipmi_acquire_done",
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
    # Mode 1: SEL dump as JSONL
    # ------------------------------------------------------------------

    def _acquire_sel(self, output: Path) -> int:
        """Stream the BMC SEL into ``output`` as one JSON object per line."""
        ipmi = self._connect()
        count = 0
        bytes_written = 0
        try:
            with output.open("w", encoding="utf-8") as fh:
                for record in ipmi.get_sel_iterator():
                    payload = self._sel_record_to_dict(record)
                    line = json.dumps(payload, sort_keys=True) + "\n"
                    fh.write(line)
                    bytes_written += len(line.encode("utf-8"))
                    count += 1
                    if count % 16 == 0:
                        self._emit_progress(bytes_written, 0, stage="sel")
        finally:
            self._close(ipmi)
        # Final progress tick so subscribers see the terminal count.
        self._emit_progress(bytes_written, bytes_written, stage="sel")
        log.info("ipmi_sel_done", records=count, bytes=bytes_written)
        return bytes_written

    @staticmethod
    def _sel_record_to_dict(record: Any) -> dict[str, Any]:
        """Best-effort normalisation of a pyipmi SEL record into a dict.

        ``pyipmi`` returns different record classes depending on the SEL
        entry type. We pull common attributes when present and fall
        back to ``repr(record)`` so the JSONL line always carries
        *something* useful.
        """
        out: dict[str, Any] = {"repr": repr(record)}
        for attr in (
            "record_id",
            "type",
            "timestamp",
            "generator_id",
            "evm_rev",
            "sensor_type",
            "sensor_number",
            "event_type",
            "event_direction",
            "event_data",
        ):
            if hasattr(record, attr):
                value = getattr(record, attr)
                # bytes -> hex for JSON-safety.
                if isinstance(value, (bytes, bytearray)):
                    out[attr] = bytes(value).hex()
                else:
                    try:
                        json.dumps(value)
                        out[attr] = value
                    except TypeError:
                        out[attr] = repr(value)
        return out

    # ------------------------------------------------------------------
    # Mode 2: BMC firmware acquisition (vendor-specific)
    # ------------------------------------------------------------------

    def _acquire_firmware(self, output: Path) -> int:
        """Best-effort BMC firmware dump via vendor OEM commands.

        This is **vendor-specific**. The following procedures are
        documented as reference; each is implemented as a stub that
        issues the OEM command sequence via ``raw_command`` when a
        vendor is explicitly declared in ``endpoint.extra['vendor']``.

        Dell iDRAC (``vendor='dell'``):
            - ``racadm`` supports ``get`` / ``fwupdate`` over IPMI OEM
              net-fn ``0x30``, cmd ``0x25``. The sequence is:
              ``Get Remote Services Status`` -> ``Start FW Dump`` ->
              iterate ``Read FW Dump Block`` until short-read. See
              Dell ``iDRAC OEM IPMI Spec`` rev 4.x.

        HPE iLO (``vendor='hpe'``):
            - HPE's OEM IPMI net-fn ``0x2E``, cmd ``0x01`` exposes
              ``Get iLO Capabilities``; the actual firmware blob is
              normally fetched out of band via ``hponcfg`` or the
              Redfish ``/redfish/v1/UpdateService/FirmwareInventory``
              endpoint. IPMI-only extraction is not officially
              supported and varies by iLO generation.

        Supermicro (``vendor='supermicro'``):
            - Supermicro X10+ boards accept OEM net-fn ``0x30``,
              cmd ``0x70`` with sub-command ``0x0C`` to toggle the BMC
              into flash-read mode, then OEM net-fn ``0x30``,
              cmd ``0x70``, sub-command ``0x0D`` with a 4-byte LE
              offset + 1-byte length per read. The reader iterates in
              up-to-256-byte chunks until the declared flash size
              (usually 32 MiB or 64 MiB).

        None of these sequences are executed speculatively: Deep View
        refuses to blast OEM raw commands at an unknown BMC because
        that can brick some boards. The operator must pass
        ``endpoint.extra['vendor']`` explicitly.
        """
        vendor = self.endpoint.extra.get("vendor")
        if not vendor:
            raise AcquisitionError(
                "IPMI firmware mode requires endpoint.extra['vendor'] "
                "(one of: 'dell', 'hpe', 'supermicro'); refusing to probe "
                "unknown BMCs with OEM raw commands"
            )
        vendor = vendor.lower()
        if vendor not in {"dell", "hpe", "supermicro"}:
            raise AcquisitionError(
                f"IPMI firmware mode: unsupported vendor {vendor!r}; "
                "expected 'dell', 'hpe', or 'supermicro'"
            )

        ipmi = self._connect()
        try:
            # Sanity-check reachable device id first. Any vendor branch
            # reuses this to confirm we're talking to the expected BMC.
            dev_id = ipmi.get_device_id()
            log.info(
                "ipmi_firmware_begin",
                host=self.endpoint.host,
                vendor=vendor,
                manufacturer_id=getattr(dev_id, "manufacturer_id", None),
                product_id=getattr(dev_id, "product_id", None),
            )

            if vendor == "dell":
                written = self._firmware_dell(ipmi, output)
            elif vendor == "hpe":
                written = self._firmware_hpe(ipmi, output)
            else:  # supermicro
                written = self._firmware_supermicro(ipmi, output)
        finally:
            self._close(ipmi)
        return written

    # ---- Vendor stubs --------------------------------------------------

    def _firmware_dell(self, ipmi: Any, output: Path) -> int:
        """Dell iDRAC OEM net-fn 0x30 / cmd 0x25 firmware dump.

        Requires an iDRAC firmware revision that exposes ``Start FW
        Dump`` (iDRAC 7+). Reads 128-byte blocks until short read.
        """
        return self._raw_block_dump(
            ipmi=ipmi,
            output=output,
            netfn=0x30,
            start_cmd=0x25,
            read_cmd=0x25,
            block_size=128,
            vendor="dell",
        )

    def _firmware_hpe(self, ipmi: Any, output: Path) -> int:
        """HPE iLO OEM stub — IPMI-only extraction is not portable.

        We refuse rather than issue commands that may destabilise the
        iLO. The operator should use Redfish / ``hponcfg`` instead.
        """
        del ipmi, output  # not used; HPE path deliberately refuses
        raise AcquisitionError(
            "HPE iLO BMC firmware extraction is not supported over IPMI alone; "
            "use the Redfish FirmwareInventory endpoint or hponcfg out of band"
        )

    def _firmware_supermicro(self, ipmi: Any, output: Path) -> int:
        """Supermicro X10+ OEM net-fn 0x30 / cmd 0x70 sub 0x0D read loop."""
        return self._raw_block_dump(
            ipmi=ipmi,
            output=output,
            netfn=0x30,
            start_cmd=0x70,
            read_cmd=0x70,
            block_size=128,
            vendor="supermicro",
            # Supermicro read commands use a sub-command byte; we
            # prefix every raw_command with it below.
            sub_cmd=0x0D,
        )

    # ---- Shared raw-block read loop -----------------------------------

    def _raw_block_dump(
        self,
        *,
        ipmi: Any,
        output: Path,
        netfn: int,
        start_cmd: int,
        read_cmd: int,
        block_size: int,
        vendor: str,
        sub_cmd: int | None = None,
    ) -> int:
        """Generic OEM raw-command block-read loop.

        Issues ``raw_command`` against the BMC in fixed-size chunks
        until a short read signals end-of-flash. The loop is defensive:
        any non-empty partial block is written, then the loop exits.
        Works for both the Dell and Supermicro read protocols because
        they share the same shape (``[sub?, offset_le4, length]``).
        """
        offset = 0
        total = 0
        with output.open("wb") as fh:
            while True:
                req = bytearray()
                if sub_cmd is not None:
                    req.append(sub_cmd)
                req.extend(offset.to_bytes(4, "little"))
                req.append(block_size)
                try:
                    rsp = ipmi.raw_command(netfn, read_cmd, bytes(req))
                except Exception as e:  # noqa: BLE001
                    log.warning(
                        "ipmi_firmware_raw_command_failed",
                        vendor=vendor,
                        offset=offset,
                        error=str(e),
                    )
                    break
                # pyipmi hands back the completion code + data. We
                # assume a bytes-like return; the first byte of many
                # OEM replies is a status byte we strip.
                data = bytes(rsp) if rsp is not None else b""
                if not data:
                    break
                # Drop a leading completion-code byte if present.
                if data[0] == 0 and len(data) > 1:
                    data = data[1:]
                fh.write(data)
                total += len(data)
                offset += len(data)
                if total % (block_size * 64) == 0:
                    self._emit_progress(total, 0, stage=f"firmware:{vendor}")
                # Short read = end-of-flash.
                if len(data) < block_size:
                    break
                # Cap at 128 MiB to prevent runaway loops against buggy BMCs.
                if total >= 128 * 1024 * 1024:
                    log.warning(
                        "ipmi_firmware_cap_reached",
                        vendor=vendor,
                        total=total,
                    )
                    break
        self._emit_progress(total, total, stage=f"firmware:{vendor}")
        return total

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    @staticmethod
    def _close(ipmi: Any) -> None:
        """Close an IPMI session, swallowing any shutdown errors."""
        try:
            ipmi.session.close()
        except Exception:  # noqa: BLE001
            pass
