"""FileVault 2 (Core Storage / APFS Encryption) unlocker adapter.

The :class:`FileVault2Unlocker` wraps the ``libfvde-python`` (``pyfvde``)
package when available. It is a *library shim*: this module does not
reimplement Core Storage decryption; it delegates to libfvde and
exposes the resulting plaintext stream as a
:class:`~deepview.interfaces.layer.DataLayer` so filesystems, carvers,
and nested unlockers can consume the decrypted bytes uniformly.

``pyfvde`` is imported **lazily** inside every method body that needs
it. A core install without the ``containers`` extra can still import
this module; only ``unlock`` raises ``RuntimeError`` when libfvde is
missing.

FileVault 2 detection
---------------------
A FileVault 2 container is either:

* a **Core Storage** volume, whose volume header starts with the ASCII
  magic ``"CS"`` at offset ``0x10`` of sector 0 (following an 8-byte
  checksum field); or
* an **APFS encrypted** volume, which libfvde also recognises via the
  APFS Container Superblock magic (``NXSB``) at offset ``0x20`` of
  the container superblock. We look for either marker and defer the
  full layout walk to libfvde at :meth:`unlock` time.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, ClassVar

from deepview.core.types import LayerMetadata, ScanResult
from deepview.interfaces.layer import DataLayer

if TYPE_CHECKING:
    from deepview.interfaces.scanner import PatternScanner
    from deepview.storage.containers.unlock import ContainerHeader, KeySource


_CORE_STORAGE_MAGIC = b"CS"
_CORE_STORAGE_MAGIC_OFFSET = 0x10
_APFS_MAGIC = b"NXSB"
_APFS_MAGIC_OFFSET = 0x20


class FileVaultDecryptedLayer(DataLayer):
    """A :class:`DataLayer` that reads plaintext from a ``pyfvde`` volume.

    Mirrors :class:`BitLockerDecryptedLayer` — the two encrypted-volume
    C libraries expose a near-identical seekable-stream API.
    """

    def __init__(
        self, volume: object, *, name: str = "filevault2-decrypted"
    ) -> None:
        self._volume = volume
        self._name = name
        try:
            self._size = int(self._volume.get_size())  # type: ignore[attr-defined]
        except Exception:
            self._size = 0

    # ------------------------------------------------------------------
    # DataLayer interface
    # ------------------------------------------------------------------

    def read(self, offset: int, length: int, *, pad: bool = False) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        if offset < 0:
            if pad:
                head = b"\x00" * min(-offset, length)
                rest = length - len(head)
                if rest <= 0:
                    return head
                return head + self.read(0, rest, pad=pad)
            raise ValueError(f"negative offset: {offset}")
        end = offset + length
        if end > self._size:
            if pad:
                take = max(0, self._size - offset)
                data = self._do_read(offset, take) if take > 0 else b""
                return data + b"\x00" * (length - len(data))
            raise ValueError(
                f"read out of bounds: offset={offset} length={length} size={self._size}"
            )
        return self._do_read(offset, length)

    def _do_read(self, offset: int, length: int) -> bytes:
        vol = self._volume
        try:
            return bytes(vol.read_buffer_at_offset(length, offset))  # type: ignore[attr-defined]
        except AttributeError:
            vol.seek_offset(offset, 0)  # type: ignore[attr-defined]
            return bytes(vol.read_buffer(length))  # type: ignore[attr-defined]

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("FileVaultDecryptedLayer is read-only")

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset and length >= 0 and offset + length <= self._size

    def scan(
        self,
        scanner: PatternScanner,
        progress_callback: Callable | None = None,
    ) -> Iterator[ScanResult]:
        remaining = self._size
        pos = 0
        chunk = 64 * 1024
        while remaining > 0:
            take = min(chunk, remaining)
            data = self.read(pos, take)
            for result in scanner.scan(data, offset=pos):
                yield result
            pos += take
            remaining -= take
            if progress_callback and self._size > 0:
                progress_callback(pos / self._size)

    @property
    def minimum_address(self) -> int:
        return 0

    @property
    def maximum_address(self) -> int:
        if self._size == 0:
            return 0
        return self._size - 1

    @property
    def metadata(self) -> LayerMetadata:
        return LayerMetadata(
            name=self._name,
            minimum_address=self.minimum_address,
            maximum_address=self.maximum_address,
        )


class FileVault2Unlocker:
    """Concrete :class:`Unlocker` for FileVault 2 (Core Storage / APFS)."""

    format_name: ClassVar[str] = "filevault2"

    def __init__(self) -> None:
        try:
            import pyfvde  # noqa: F401

            self._pyfvde_available = True
        except Exception:
            self._pyfvde_available = False

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(
        self, layer: DataLayer, offset: int = 0
    ) -> ContainerHeader | None:
        """Return a :class:`ContainerHeader` if *layer* looks like FileVault 2."""
        from deepview.storage.containers.unlock import ContainerHeader

        try:
            head = layer.read(offset, 4096, pad=True)
        except Exception:
            return None
        if len(head) < max(
            _CORE_STORAGE_MAGIC_OFFSET + len(_CORE_STORAGE_MAGIC),
            _APFS_MAGIC_OFFSET + len(_APFS_MAGIC),
        ):
            return None

        cs_sig = head[
            _CORE_STORAGE_MAGIC_OFFSET : _CORE_STORAGE_MAGIC_OFFSET
            + len(_CORE_STORAGE_MAGIC)
        ]
        apfs_sig = head[
            _APFS_MAGIC_OFFSET : _APFS_MAGIC_OFFSET + len(_APFS_MAGIC)
        ]
        if cs_sig != _CORE_STORAGE_MAGIC and apfs_sig != _APFS_MAGIC:
            return None

        try:
            size = int(layer.maximum_address) + 1
        except Exception:
            size = 0
        return ContainerHeader(
            format="filevault2",
            cipher="aes-xts",
            sector_size=512,
            data_offset=0,
            data_length=max(0, size - offset),
            kdf="pbkdf2_sha256",
            kdf_params={"iterations": 41000, "dklen": 16},
            raw=head,
        )

    # ------------------------------------------------------------------
    # Unlock
    # ------------------------------------------------------------------

    async def unlock(
        self,
        layer: DataLayer,
        header: ContainerHeader,
        source: KeySource,
        *,
        try_hidden: bool = False,
    ) -> DataLayer:
        """Open *layer* via ``pyfvde`` and return a :class:`DataLayer`."""
        try:
            import pyfvde
        except ImportError as e:
            raise RuntimeError(
                "pyfvde required for FileVault 2 unlock; install via "
                "`pip install libfvde-python`"
            ) from e

        from deepview.storage.containers._layer_file_io import LayerFileIO
        from deepview.storage.containers.unlock import (
            Keyfile,
            MasterKey,
            Passphrase,
        )

        file_io = LayerFileIO(layer)
        volume = pyfvde.volume()  # type: ignore[attr-defined]

        if isinstance(source, Passphrase):
            pw = source.passphrase
            # Core Storage recovery keys look like
            # ``XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`` (24 alnum chars, grouped).
            if _looks_like_recovery_key(pw):
                try:
                    volume.set_recovery_password(pw)  # type: ignore[attr-defined]
                except Exception:
                    volume.set_password(pw)  # type: ignore[attr-defined]
            else:
                try:
                    volume.set_password(pw)  # type: ignore[attr-defined]
                except Exception:
                    volume.set_recovery_password(pw)  # type: ignore[attr-defined]
        elif isinstance(source, MasterKey):
            # Volume Key Data extracted from memory / kernel.
            volume.set_volume_key_data(source.key)  # type: ignore[attr-defined]
        elif isinstance(source, Keyfile):
            # libfvde accepts a KEK as raw bytes from a file. Hash-by-SHA256
            # is the LUKS / VeraCrypt convention; FileVault instead uses
            # the file contents directly as key data.
            from pathlib import Path

            raw = Path(source.path).read_bytes()
            volume.set_volume_key_data(raw)  # type: ignore[attr-defined]
        else:
            raise RuntimeError(
                f"unsupported key source for FileVault 2: {type(source).__name__}"
            )

        try:
            volume.open_file_object(file_io)  # type: ignore[attr-defined]
        except Exception as e:
            raise RuntimeError(f"FileVault 2 open failed: {e}") from e

        return FileVaultDecryptedLayer(volume, name="filevault2-decrypted")


def _looks_like_recovery_key(pw: str) -> bool:
    """Heuristic: Core Storage recovery keys are 6 groups of 4 alnum chars."""
    parts = pw.strip().split("-")
    if len(parts) != 6:
        return False
    return all(len(p) == 4 and p.isalnum() for p in parts)


# Module-level hook consumed by :class:`UnlockOrchestrator`.
UNLOCKER = FileVault2Unlocker


__all__ = [
    "FileVault2Unlocker",
    "FileVaultDecryptedLayer",
    "UNLOCKER",
]
