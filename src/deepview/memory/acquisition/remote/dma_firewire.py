"""FireWire (IEEE-1394) DMA acquisition provider.

Uses the ``forensic1394`` Python bindings to perform physical memory
reads over a FireWire bus. FireWire DMA is the original physical-memory
attack vector; like the Thunderbolt / PCIe paths it requires root
locally and is likely to be refused if the host's IOMMU blocks
untrusted bus-master requests.

Operator notes:

- ``endpoint.extra["bus_id"]`` optionally pins to a specific FireWire
  device (the ``guid`` reported by ``forensic1394``). Without it we use
  the first enumerated device.
- ``endpoint.extra["max_bytes"]`` bounds the read (default 4 GiB — most
  FireWire OHCI controllers are 32-bit and cannot reach above this).
- Many modern Macs and Linux distros disable FireWire DMA by default
  (``CONFIG_FIREWIRE_OHCI_REMOTE_DMA=n``); if so, ``read()`` will
  return zeroes rather than memory.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from deepview.core.events import (
    RemoteAcquisitionCompletedEvent,
    RemoteAcquisitionProgressEvent,
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

log = get_logger("memory.acquisition.remote.dma_firewire")


_DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB
_CHUNK_SIZE = 1024 * 1024


def _is_root() -> bool:
    """Return True when the current process has root / admin privilege."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0  # type: ignore[attr-defined,no-any-return]
    if sys.platform.startswith("win"):
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return False


def _detect_iommu_state() -> tuple[bool, str]:
    """Duplicate of the other DMA providers' IOMMU probe — see docstring
    in :mod:`dma_thunderbolt`.
    """
    try:
        iommu_dir = "/sys/class/iommu"
        if os.path.isdir(iommu_dir):
            entries = os.listdir(iommu_dir)
            if entries:
                efivars = "/sys/firmware/efi/efivars"
                setup_mode_locked = False
                if os.path.isdir(efivars):
                    try:
                        for name in os.listdir(efivars):
                            if name.startswith("SetupMode-"):
                                setup_mode_locked = True
                                break
                    except OSError:
                        pass
                desc = (
                    f"iommu-active groups={len(entries)} "
                    f"setup-mode-locked={setup_mode_locked}"
                )
                return True, desc
            return False, "iommu-dir-empty"
        cpuinfo = "/proc/cpuinfo"
        if os.path.isfile(cpuinfo):
            try:
                with open(cpuinfo) as fh:
                    text = fh.read()
            except OSError:
                text = ""
            flags = ("vmx", "svm", "smx")
            seen = [f for f in flags if f" {f} " in text or text.startswith(f"{f} ")]
            if seen:
                return False, f"iommu-unknown cpu-flags={','.join(seen)}"
        return False, "iommu-unknown"
    except Exception as exc:  # noqa: BLE001
        return False, f"iommu-probe-failed: {exc}"


class FireWireDMAProvider(RemoteAcquisitionProvider):
    """Acquire physical memory over FireWire via ``forensic1394``."""

    @classmethod
    def provider_name(cls) -> str:
        return "dma-firewire"

    def transport_name(self) -> str:
        return "dma-fw"

    def is_available(self) -> bool:
        try:
            import forensic1394  # noqa: F401
        except Exception:  # noqa: BLE001
            log.debug("dma_fw_forensic1394_missing")
            return False
        if not _is_root():
            log.debug("dma_fw_not_root")
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS]

    def requires_privileges(self) -> PrivilegeLevel:
        return PrivilegeLevel.ROOT

    def acquire(
        self,
        target: AcquisitionTarget,
        output: Path,
        fmt: DumpFormat = DumpFormat.RAW,
    ) -> AcquisitionResult:
        if not _is_root():
            raise RuntimeError("DMA acquisition requires root privileges")

        max_bytes_raw = self.endpoint.extra.get("max_bytes")
        max_bytes = int(max_bytes_raw) if max_bytes_raw is not None else _DEFAULT_MAX_BYTES
        bus_id = self.endpoint.extra.get("bus_id")

        locked, iommu_desc = _detect_iommu_state()
        self._context.events.publish(
            RemoteAcquisitionProgressEvent(
                endpoint=self.endpoint.host,
                bytes_done=0,
                bytes_total=max_bytes,
                stage=f"iommu-check {iommu_desc}",
            )
        )
        if locked:
            log.warning(
                "dma_fw_iommu_locked",
                note="DMA likely to fail; attempting anyway",
                iommu_desc=iommu_desc,
            )
        else:
            log.info("dma_fw_iommu_state", iommu_desc=iommu_desc)

        try:
            import forensic1394
        except ImportError as e:
            raise AcquisitionError(
                "forensic1394 is required for FireWire DMA acquisition "
                "(pip install 'deepview[remote_acquisition]')"
            ) from e

        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )

        bus = forensic1394.Bus()
        devices = list(bus.devices())
        if not devices:
            raise AcquisitionError("forensic1394: no FireWire devices found on the bus")

        selected = None
        if bus_id is not None:
            for dev in devices:
                # forensic1394 devices expose ``guid`` as an int; compare
                # against both the decimal and hex-string forms.
                guid = getattr(dev, "guid", None)
                if guid is None:
                    continue
                if str(guid) == str(bus_id) or hex(int(guid)) == str(bus_id).lower():
                    selected = dev
                    break
            if selected is None:
                raise AcquisitionError(
                    f"forensic1394: no device matching bus_id={bus_id!r} "
                    f"(found {len(devices)} devices)"
                )
        else:
            selected = devices[0]

        log.info(
            "dma_fw_selected_device",
            guid=getattr(selected, "guid", None),
            vendor=getattr(selected, "vendor_name", None),
            product=getattr(selected, "product_name", None),
        )

        size_bytes = 0
        try:
            selected.open()
            try:
                with open(output, "wb") as dst:
                    addr = 0
                    while addr < max_bytes:
                        to_read = min(_CHUNK_SIZE, max_bytes - addr)
                        try:
                            chunk = selected.read(addr, to_read)
                        except Exception as exc:  # noqa: BLE001
                            log.error(
                                "dma_fw_read_failed",
                                addr=addr,
                                size=to_read,
                                error=str(exc),
                            )
                            self._context.events.publish(
                                RemoteAcquisitionCompletedEvent(
                                    endpoint=self.endpoint.host,
                                    output=str(output),
                                    size_bytes=size_bytes,
                                    elapsed_s=time.time() - start,
                                )
                            )
                            raise
                        if not chunk:
                            break
                        dst.write(chunk)
                        size_bytes += len(chunk)
                        addr += len(chunk)
                        self._emit_progress(size_bytes, max_bytes, stage="stream")
            finally:
                try:
                    selected.close()
                except Exception:  # noqa: BLE001
                    pass
        except Exception:
            raise

        elapsed = time.time() - start
        self._context.events.publish(
            RemoteAcquisitionCompletedEvent(
                endpoint=self.endpoint.host,
                output=str(output),
                size_bytes=size_bytes,
                elapsed_s=elapsed,
            )
        )
        log.info("dma_fw_done", size_bytes=size_bytes, elapsed_s=elapsed)
        return AcquisitionResult(
            success=True,
            output_path=output,
            format=fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )
