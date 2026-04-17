"""PCIe DMA acquisition provider.

Same leechcore path as the Thunderbolt provider but oriented at
dedicated PCIe capture cards (PCILeech, ScreamerM2, FT2232H-based
boards). The default leechcore device string is ``pmem``; operators can
override via ``endpoint.extra["device"]`` (for example ``ft2232h`` or a
specific PCILeech variant).

Root is mandatory locally; IOMMU / VT-d lock state is probed and
surfaced through a :class:`RemoteAcquisitionProgressEvent` before any
DMA traffic is attempted. If the IOMMU is locked the read will almost
certainly fail, but Deep View attempts it anyway — a clear failure mode
is preferable to silently refusing.
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

log = get_logger("memory.acquisition.remote.dma_pcie")


_DEFAULT_DEVICE = "pmem"
_DEFAULT_MAX_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB
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
    """Mirror of :func:`dma_thunderbolt._detect_iommu_state`.

    Kept inline rather than imported cross-module because slice 20
    scopes edits to the four provider files only; if we grow a shared
    ``dma_common.py`` in the future the two halves collapse to one
    function.
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


class PCIeDMAProvider(RemoteAcquisitionProvider):
    """Acquire physical memory over a PCIe capture device via leechcore."""

    @classmethod
    def provider_name(cls) -> str:
        return "dma-pcie"

    def transport_name(self) -> str:
        return "dma-pcie"

    def is_available(self) -> bool:
        try:
            import leechcorepyc  # noqa: F401
        except Exception:  # noqa: BLE001
            log.debug("dma_pcie_leechcore_missing")
            return False
        if not _is_root():
            log.debug("dma_pcie_not_root")
            return False
        return True

    def supported_platforms(self) -> list[Platform]:
        return [Platform.LINUX, Platform.WINDOWS]

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
                "dma_pcie_iommu_locked",
                note="DMA likely to fail; attempting anyway",
                iommu_desc=iommu_desc,
            )
        else:
            log.info("dma_pcie_iommu_state", iommu_desc=iommu_desc)

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
        log.info("dma_pcie_init", device=device, max_bytes=max_bytes)

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
                            "dma_pcie_read_failed",
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
        log.info("dma_pcie_done", size_bytes=size_bytes, elapsed_s=elapsed)
        return AcquisitionResult(
            success=True,
            output_path=output,
            format=fmt,
            size_bytes=size_bytes,
            duration_seconds=elapsed,
        )
