"""Thunderbolt DMA acquisition provider.

Uses the ``leechcorepyc`` bindings (from the ``leechcore`` PyPI package
that is already declared under ``[hardware]``) to read physical memory
over a Thunderbolt / PCIe capture device. This is a dual-use capability
— it requires root locally and will very likely fail if the host's
IOMMU (Intel VT-d / AMD-Vi) is locked, as is typical on modern boxes.

Scope: scope this to authorized incident response, CTF, or defensive
research. Deep View emits a progress event with the IOMMU state before
attempting the read so the operator has a clear record of what was
attempted and why it may have failed.
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

log = get_logger("memory.acquisition.remote.dma_thunderbolt")


_DEFAULT_DEVICE = "pcileech"
_DEFAULT_MAX_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB
_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _is_root() -> bool:
    """Return True when the current process has root / admin privilege.

    On POSIX this is ``os.geteuid() == 0``; on Windows we treat any
    non-zero result from :func:`ctypes.windll.shell32.IsUserAnAdmin` as
    True. Any error is treated as non-admin (fail-safe).
    """
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
    """Detect whether the host's IOMMU is likely enabled + locked.

    Returns ``(likely_locked, description)``. ``likely_locked`` is a
    best-effort boolean: True means DMA will probably be rejected.

    Coverage:
    - Linux: ``/sys/class/iommu/`` — non-empty means an IOMMU is live.
    - Linux: ``/sys/firmware/efi/efivars/SetupMode-*`` — presence hints
      that UEFI Setup-Mode is off (SetupMode=0 = locked). We only check
      existence here, which is a coarse signal but matches the plan's
      documented heuristic.
    - Other platforms: ``/proc/cpuinfo`` flags (``vmx``, ``svm``, ``smx``)
      as a best-effort indicator that virtualization extensions are at
      least available; we do not claim to detect actual IOMMU state.
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


class ThunderboltDMAProvider(RemoteAcquisitionProvider):
    """Acquire physical memory over Thunderbolt/PCIe via leechcore."""

    @classmethod
    def provider_name(cls) -> str:
        return "dma-thunderbolt"

    def transport_name(self) -> str:
        return "dma-tb"

    def is_available(self) -> bool:
        try:
            import leechcorepyc  # noqa: F401
        except Exception:  # noqa: BLE001
            log.debug("dma_tb_leechcore_missing")
            return False
        if not _is_root():
            log.debug("dma_tb_not_root")
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.MACOS, Platform.WINDOWS]

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

        device = self.endpoint.extra.get("device", _DEFAULT_DEVICE)
        max_bytes_raw = self.endpoint.extra.get("max_bytes")
        max_bytes = int(max_bytes_raw) if max_bytes_raw is not None else _DEFAULT_MAX_BYTES

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
                "dma_tb_iommu_locked",
                note="DMA likely to fail; attempting anyway",
                iommu_desc=iommu_desc,
            )
        else:
            log.info("dma_tb_iommu_state", iommu_desc=iommu_desc)

        try:
            import leechcorepyc
        except ImportError as e:
            raise AcquisitionError(
                "leechcorepyc is required for DMA acquisition "
                "(pip install 'deepview[hardware]')"
            ) from e

        start = time.time()
        self._context.events.publish(
            RemoteAcquisitionStartedEvent(
                endpoint=self.endpoint.host,
                transport=self.transport_name(),
                output=str(output),
            )
        )
        log.info("dma_tb_init", device=device, max_bytes=max_bytes)

        size_bytes = 0
        lc: object | None = None
        try:
            lc = leechcorepyc.LeechCore(device)
            with open(output, "wb") as dst:
                addr = 0
                while addr < max_bytes:
                    to_read = min(_CHUNK_SIZE, max_bytes - addr)
                    try:
                        chunk = lc.read(addr, to_read)  # type: ignore[attr-defined]
                    except Exception as exc:  # noqa: BLE001
                        log.error(
                            "dma_tb_read_failed",
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
                        # Device returned nothing — treat as end-of-memory.
                        break
                    dst.write(chunk)
                    size_bytes += len(chunk)
                    addr += len(chunk)
                    self._emit_progress(size_bytes, max_bytes, stage="stream")
        finally:
            if lc is not None:
                try:
                    lc.close()  # type: ignore[attr-defined]
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
        log.info("dma_tb_done", size_bytes=size_bytes, elapsed_s=elapsed)
        return AcquisitionResult(
            success=True,
            output_path=output,
            format=fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )
